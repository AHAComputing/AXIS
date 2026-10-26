//! Hardware netlist IR.
//!
//! `emit-pyrtl` builds one circuit per instruction by interpreting the
//! semantics *string* at elaboration time. Nothing in that shape can be
//! analysed: there is no netlist until Python has run, so nothing can say how
//! big an instruction is, how deep, or which two instructions want the same
//! adder. See `docs/hardware_design.md`.
//!
//! This module is the structure that was missing. [`lower_expr`] turns the
//! typed IR ([`crate::ir::Sem`]) into a hash-consed graph of a small set of
//! hardware primitives, each node carrying its exact width. Three decisions
//! shape it:
//!
//! * **Polymorphism lives in control inputs, not in operator names.** There is
//!   one adder primitive, [`HwOp::AddSub`], whose third argument says whether
//!   it subtracts; `add`, `sub`, `icmp_ult`, `icmp_slt`, `min` and `max` all
//!   lower onto it. One right shifter ([`HwOp::Shr`]) whose third argument is
//!   the bit shifted in serves `lshr`, `ashr` and -- between two bit reversals,
//!   which are wires -- `shl`. So `SUB`, `SLT` and `SLTU` share a subtractor by
//!   hash-consing alone, and merging instructions into a functional unit
//!   (`crate::hw_units`) only ever has to bind a node to a unit of the *same*
//!   primitive and mux its inputs, control inputs included.
//! * **Widths are demanded, not inherited.** `lower(sem, n)` returns an
//!   `n`-bit node congruent to the golden model's value modulo `2^n`, and asks
//!   each argument for only the bits that can reach those `n`. `ADDW`'s
//!   `(sext i64 32 (add i32 rs1 rs2))` therefore builds a 32-bit adder, not a
//!   64-bit one whose top half is thrown away.
//! * **Every rewrite is a builder.** Constant folding and the wiring identities
//!   (a shift by a constant is a slice and a concat; `x & 0x3f` is a slice and
//!   a zero-extension) happen where a node is made, so there is no pass that
//!   could be skipped and no node that escapes them.
//!
//! The semantics a node must match is the golden model's, which evaluates in
//! unbounded integers and masks only where an operator says so. Each arm of
//! [`Scope::lower_node`] states the congruence it relies on.

use std::collections::HashMap;

use crate::ast::{Document, Function};
use crate::ir::{self, Op, Sem};
use crate::semantics::{parse_formal_semantics, SemanticExpr};

pub type NodeId = usize;

/// The widest value a node may carry. The graph's interpreter and its constant
/// folder hold values in a `u128`, and a description wider than that is
/// declined by name rather than computed in something narrower.
pub const MAX_WIDTH: u32 = 128;

/// The name of a merged unit's instruction-select input. Not an identifier a
/// description can write, so it cannot collide with an operand.
pub const SELECT_INPUT: &str = "%sel";

pub fn mask(width: u32) -> u128 {
    if width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    }
}

/// Bits needed to hold the value `n` itself: the width of a count that can
/// reach `n`.
pub fn bit_length(n: u32) -> u32 {
    32 - n.leading_zeros()
}

pub fn ceil_log2(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        32 - (n - 1).leading_zeros()
    }
}

/// A hardware primitive. Argument order and result width are part of the
/// definition; [`eval_op`] is the definition's other half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HwOp {
    /// A named input, `name` wide.
    Input,
    /// `value`.
    Const,
    /// `[a, b, sub]`, `a` and `b` both `n` wide, `sub` one bit. The result is
    /// `n + 1` wide: `a + (sub ? ~b : b) + sub`, whose top bit is the carry
    /// out. Subtracting, the carry is set exactly when `a >= b` unsigned.
    AddSub,
    /// `[a, b]` -> the low `n` bits of the product.
    Mul,
    /// `[a, b, sa, sb]` -> the full `2n`-bit product, reading `a` as signed
    /// when `sa` is set and `b` as signed when `sb` is.
    MulWide,
    /// `[a, b, signed]` -> `2n` bits, the remainder above the quotient.
    /// Division truncates toward zero, the remainder takes the dividend's
    /// sign, and a zero divisor gives zero for both -- AXIS's `udiv`/`sdiv`/
    /// `urem`/`srem`, which specify it rather than inherit a host's trap.
    DivRem,
    /// `[a, amount, fill]` -> `a` shifted right by `amount`, `fill` shifted
    /// in. `amount` is an unsigned number of any width; at or past `n` every
    /// bit is `fill`.
    Shr,
    /// `[a, amount]` -> `a` rotated right. `n` is a power of two and `amount`
    /// is exactly `log2 n` bits.
    Ror,
    /// `[a]` -> leading zeros, `bit_length(n)` wide; `n` for a zero input.
    Clz,
    /// `[a]` -> set bits, `bit_length(n)` wide.
    Cpop,
    /// `[a, b]` -> one bit.
    Eq,
    And,
    Or,
    Xor,
    Not,
    /// `[sel, then, else]`, `sel` one bit.
    Mux,
    Zext,
    Sext,
    /// `[a]` -> bits `[value, value + width)` of `a`.
    Slice,
    /// `[hi, lo]`.
    Concat,
    /// `[a]` -> `a` with its bits in the opposite order.
    Rev,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HwNode {
    pub op: HwOp,
    pub width: u32,
    pub args: Vec<NodeId>,
    /// A constant's value, or a slice's low bit; zero otherwise.
    pub value: u128,
    /// An input's name; empty otherwise.
    pub name: String,
}

/// What one primitive computes, on values paired with their widths. The
/// constant folder, the graph interpreter and the unit tests all go through
/// this, so there is one statement of each primitive to keep the PyRTL helpers
/// honest against.
pub fn eval_op(op: HwOp, width: u32, value: u128, args: &[(u128, u32)]) -> u128 {
    let m = mask(width);
    let arg = |index: usize| args[index].0;
    match op {
        HwOp::Input => unreachable!("an input has no definition to evaluate"),
        HwOp::Const => value & m,
        HwOp::AddSub => {
            let n = args[0].1;
            let sub = arg(2) & 1;
            let b = if sub == 1 { !arg(1) & mask(n) } else { arg(1) };
            (arg(0) + b + sub) & m
        }
        HwOp::Mul => arg(0).wrapping_mul(arg(1)) & m,
        HwOp::MulWide => {
            let n = args[0].1;
            let read = |value: u128, signed: u128| -> i128 {
                if signed & 1 == 1 && (value >> (n - 1)) & 1 == 1 {
                    value as i128 - (1i128 << n)
                } else {
                    value as i128
                }
            };
            (read(arg(0), arg(2)).wrapping_mul(read(arg(1), arg(3))) as u128) & m
        }
        HwOp::DivRem => {
            let n = args[0].1;
            let (a, b) = (arg(0), arg(1));
            if b == 0 {
                return 0;
            }
            let (quotient, remainder) = if arg(2) & 1 == 1 {
                let read = |value: u128| -> i128 {
                    if (value >> (n - 1)) & 1 == 1 {
                        value as i128 - (1i128 << n)
                    } else {
                        value as i128
                    }
                };
                let (a, b) = (read(a), read(b));
                (a.wrapping_div(b) as u128, a.wrapping_rem(b) as u128)
            } else {
                (a / b, a % b)
            };
            ((remainder & mask(n)) << n) | (quotient & mask(n))
        }
        HwOp::Shr => {
            let n = args[0].1;
            let fill = arg(2) & 1 == 1;
            if arg(1) >= n as u128 {
                return if fill { mask(n) } else { 0 };
            }
            let amount = arg(1) as u32;
            let mut out = arg(0) >> amount;
            if fill && amount > 0 {
                out |= mask(n) & !(mask(n) >> amount);
            }
            out
        }
        HwOp::Ror => {
            let n = args[0].1;
            let amount = (arg(1) % n as u128) as u32;
            if amount == 0 {
                arg(0)
            } else {
                ((arg(0) >> amount) | (arg(0) << (n - amount))) & mask(n)
            }
        }
        HwOp::Clz => (args[0].1 - (128 - arg(0).leading_zeros())) as u128,
        HwOp::Cpop => arg(0).count_ones() as u128,
        HwOp::Eq => (arg(0) == arg(1)) as u128,
        HwOp::And => arg(0) & arg(1),
        HwOp::Or => arg(0) | arg(1),
        HwOp::Xor => arg(0) ^ arg(1),
        HwOp::Not => !arg(0) & m,
        HwOp::Mux => {
            if arg(0) & 1 == 1 {
                arg(1)
            } else {
                arg(2)
            }
        }
        HwOp::Zext => arg(0),
        HwOp::Sext => {
            let from = args[0].1;
            if (arg(0) >> (from - 1)) & 1 == 1 {
                arg(0) | (m & !mask(from))
            } else {
                arg(0)
            }
        }
        HwOp::Slice => (arg(0) >> value as u32) & m,
        HwOp::Concat => (arg(0) << args[1].1) | arg(1),
        HwOp::Rev => arg(0).reverse_bits() >> (128 - args[0].1),
    }
}

/// A hash-consed netlist. A node's arguments always have smaller ids than the
/// node, so ascending id order is a topological order -- which every pass here
/// relies on instead of sorting.
#[derive(Default)]
pub struct HwGraph {
    pub nodes: Vec<HwNode>,
    interned: HashMap<HwNode, NodeId>,
    /// Per node, the bits that are the same on every input. See [`KnownBits`].
    known: Vec<KnownBits>,
    /// Per node, the values each of its bits is a function of the same bit
    /// of, when that is a short list. See [`HwGraph::bitwise_support`].
    support: Vec<Option<Box<[NodeId]>>>,
}

/// The longest list of values a node is recorded as a bit-by-bit function of.
const SUPPORT_LIMIT: usize = 16;

/// The bits of a value that no input can change: `zeros` are always clear
/// and `ones` always set.
///
/// The builders fold what is constant as a whole; this is the rest -- a
/// zero-extension's upper half, a mask's cleared bits, the arm of a mux that
/// is a literal. Nothing is rewritten on its account. It is what the cost
/// model reads to charge for the gates synthesis will leave, and not for a
/// 64-bit mux of which 32 bits are a wire to ground.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KnownBits {
    pub zeros: u128,
    pub ones: u128,
}

impl KnownBits {
    fn any(self) -> u128 {
        self.zeros | self.ones
    }
}

/// Area in NAND2 equivalents and delay in gate delays.
///
/// Calibrated: every constant below is fitted to what the emitted PyRTL comes
/// to when Yosys and ABC map it to SkyWater's 130 nm high-density cells at the
/// typical corner (`tools/hw_synth.py` is the flow, `tools/hw_calibrate.py
/// --operators` the sweep the fits were made on, at 8, 16, 32 and 64 bits).
/// A NAND2 equivalent is the area of that library's `nand2_1`, and a gate
/// delay is [`PS_PER_GATE`] picoseconds in it.
///
/// ⚠️ It is a model of THESE netlists under THAT flow: synthesis without
/// placement or wire load, and operators costed one at a time, so logic that
/// synthesis shares or simplifies across two operators is counted twice.
/// `tools/hw_calibrate.py` says how far that is from the measurement, on every
/// instruction and unit of a corpus, and fails if it grows.
pub const PS_PER_GATE: f64 = 100.0;
/// The area of one NAND2 equivalent in the reference library:
/// `sky130_fd_sc_hd__nand2_1`, in square micrometres.
pub const NAND2_UM2: f64 = 3.7536;
/// What the constants were fitted to; published in `emit-hw-json`.
pub const COST_REFERENCE: &str = "yosys+abc, sky130_fd_sc_hd tt 1.80V 25C, no wire load";
pub const GE_NOT: f64 = 1.0;
pub const GE_AND: f64 = 1.67;
pub const GE_XOR: f64 = 2.33;
pub const GE_MUX: f64 = 3.0;
/// What a second shifter of the same value by the same amount costs, as a
/// share of the first.
pub const SHIFTER_AGAIN: f64 = 0.45;
/// A mux that brings no new value into its tree, as a share of one that does.
pub const MUX_REPEATED: f64 = 0.25;
/// What a mux saves for each of its arms that is itself a mux.
pub const GE_MUX_NESTED: f64 = 0.95;
/// A mux inside a tree of them -- a shifter's row, a rotator's -- where
/// synthesis folds neighbouring rows together.
pub const GE_MUX_ROW: f64 = 2.8;
pub const DELAY_NOT: f64 = 0.1;
pub const DELAY_AND: f64 = 1.0;
pub const DELAY_XOR: f64 = 1.2;
pub const DELAY_MUX: f64 = 2.0;
/// A prefix adder's cells per bit.
pub const GE_ADDER_BIT: f64 = 9.8;
/// A bit that only makes a carry: a comparator's.
pub const GE_CARRY_BIT: f64 = 6.0;
/// The same two with one operand bit known: an incrementer's bit, and a bit
/// of a comparison against a constant.
pub const GE_HALF_ADDER_BIT: f64 = 4.3;
pub const GE_HALF_CARRY_BIT: f64 = 1.8;
/// And with one operand bit a copy of the bit below it: the upper bits of a
/// sign-extended immediate.
pub const GE_REPEAT_ADDER_BIT: f64 = 7.8;
pub const GE_REPEAT_CARRY_BIT: f64 = 2.3;
/// The XOR in front of an adder that subtracts on a signal.
pub const GE_SUB_XOR_BIT: f64 = 2.7;
pub const EQ_BIT: f64 = 3.0;
pub const EQ_CONST_BIT: f64 = 0.7;
/// A multiplier is its partial products, less what the edges of the array
/// do not need.
pub const GE_PRODUCT_BIT: f64 = 10.2;
pub const GE_PRODUCT_EDGE: f64 = 13.0;

impl HwGraph {
    pub fn node(&self, id: NodeId) -> &HwNode {
        &self.nodes[id]
    }

    pub fn width(&self, id: NodeId) -> u32 {
        self.nodes[id].width
    }

    pub fn as_const(&self, id: NodeId) -> Option<u128> {
        let node = &self.nodes[id];
        (node.op == HwOp::Const).then_some(node.value)
    }

    fn intern(&mut self, op: HwOp, width: u32, args: Vec<NodeId>, value: u128, name: &str) -> NodeId {
        debug_assert!(width >= 1 && width <= MAX_WIDTH, "{op:?} at width {width}");
        let node = HwNode { op, width, args, value, name: name.to_string() };
        if let Some(id) = self.interned.get(&node) {
            return *id;
        }
        let id = self.nodes.len();
        self.known.push(self.known_of(&node));
        self.support.push(self.support_of(&node));
        self.nodes.push(node.clone());
        self.interned.insert(node, id);
        id
    }

    pub fn known(&self, id: NodeId) -> KnownBits {
        self.known[id]
    }

    /// The values `id` is a bit-by-bit function of: bit `i` of it depends on
    /// bit `i` of each and on nothing else of them. Gates, muxes (through
    /// their arms) and zero-extensions have such a list; anything else is one
    /// value, itself.
    ///
    /// It is what tells a mux of `a & b`, `a | b` and `a ^ b` -- three arms,
    /// two values, one small function of each bit -- from a mux of an adder,
    /// a shifter and a multiplier.
    pub fn bitwise_support(&self, id: NodeId) -> Vec<NodeId> {
        match &self.support[id] {
            Some(list) => list.to_vec(),
            None if self.nodes[id].op == HwOp::Const => Vec::new(),
            None => vec![id],
        }
    }

    fn support_of(&self, node: &HwNode) -> Option<Box<[NodeId]>> {
        let args: &[NodeId] = match node.op {
            HwOp::And | HwOp::Or | HwOp::Xor | HwOp::Not | HwOp::Zext => &node.args,
            HwOp::Slice if node.value == 0 => &node.args,
            HwOp::Mux => &node.args[1..],
            _ => return None,
        };
        let mut list: Vec<NodeId> = args.iter().flat_map(|arg| self.bitwise_support(*arg)).collect();
        list.sort_unstable();
        list.dedup();
        (list.len() <= SUPPORT_LIMIT).then(|| list.into_boxed_slice())
    }

    fn known_of(&self, node: &HwNode) -> KnownBits {
        let full = mask(node.width);
        let arg = |index: usize| self.known[node.args[index]];
        let arg_width = |index: usize| self.nodes[node.args[index]].width;
        let (zeros, ones) = match node.op {
            HwOp::Const => (!node.value, node.value),
            HwOp::Zext => (arg(0).zeros | !mask(arg_width(0)), arg(0).ones),
            HwOp::Sext => {
                let from = arg_width(0);
                let (top, upper) = (1u128 << (from - 1), full & !mask(from));
                let known = arg(0);
                (
                    known.zeros & mask(from) | if known.zeros & top != 0 { upper } else { 0 },
                    known.ones | if known.ones & top != 0 { upper } else { 0 },
                )
            }
            HwOp::Slice => (arg(0).zeros >> node.value, arg(0).ones >> node.value),
            HwOp::Concat => {
                let low = arg_width(1);
                (
                    arg(0).zeros << low | arg(1).zeros & mask(low),
                    arg(0).ones << low | arg(1).ones,
                )
            }
            HwOp::Not => (arg(0).ones, arg(0).zeros),
            HwOp::And => (arg(0).zeros | arg(1).zeros, arg(0).ones & arg(1).ones),
            HwOp::Or => (arg(0).zeros & arg(1).zeros, arg(0).ones | arg(1).ones),
            HwOp::Xor => (
                arg(0).zeros & arg(1).zeros | arg(0).ones & arg(1).ones,
                arg(0).zeros & arg(1).ones | arg(0).ones & arg(1).zeros,
            ),
            HwOp::Mux => (arg(1).zeros & arg(2).zeros, arg(1).ones & arg(2).ones),
            _ => (0, 0),
        };
        KnownBits { zeros: zeros & full, ones: ones & full }
    }

    /// Fold a node whose arguments are all constants.
    fn fold(&mut self, op: HwOp, width: u32, value: u128, args: &[NodeId]) -> Option<NodeId> {
        let mut values = Vec::with_capacity(args.len());
        for arg in args {
            values.push((self.as_const(*arg)?, self.width(*arg)));
        }
        let folded = eval_op(op, width, value, &values);
        Some(self.konst(folded, width))
    }

    pub fn input(&mut self, name: &str, width: u32) -> NodeId {
        self.intern(HwOp::Input, width, Vec::new(), 0, name)
    }

    pub fn konst(&mut self, value: u128, width: u32) -> NodeId {
        self.intern(HwOp::Const, width, Vec::new(), value & mask(width), "")
    }

    pub fn slice(&mut self, a: NodeId, lo: u32, width: u32) -> NodeId {
        let source = self.width(a);
        debug_assert!(width >= 1 && lo + width <= source);
        if lo == 0 && width == source {
            return a;
        }
        let node = self.nodes[a].clone();
        match node.op {
            HwOp::Const => return self.konst(node.value >> lo, width),
            HwOp::Slice => return self.slice(node.args[0], node.value as u32 + lo, width),
            HwOp::Zext | HwOp::Sext => {
                let inner = node.args[0];
                let inner_width = self.width(inner);
                if lo + width <= inner_width {
                    return self.slice(inner, lo, width);
                }
                if lo >= inner_width {
                    // Nothing but extension bits.
                    if node.op == HwOp::Zext {
                        return self.konst(0, width);
                    }
                    let sign = self.slice(inner, inner_width - 1, 1);
                    return self.sext(sign, width);
                }
                if lo == 0 {
                    return if node.op == HwOp::Zext {
                        self.zext(inner, width)
                    } else {
                        self.sext(inner, width)
                    };
                }
            }
            HwOp::Concat => {
                let (hi, low) = (node.args[0], node.args[1]);
                let low_width = self.width(low);
                if lo + width <= low_width {
                    return self.slice(low, lo, width);
                }
                if lo >= low_width {
                    return self.slice(hi, lo - low_width, width);
                }
                let upper = self.slice(hi, 0, lo + width - low_width);
                let lower = self.slice(low, lo, low_width - lo);
                return self.concat(upper, lower);
            }
            _ => {}
        }
        self.intern(HwOp::Slice, width, vec![a], lo as u128, "")
    }

    pub fn zext(&mut self, a: NodeId, width: u32) -> NodeId {
        let source = self.width(a);
        debug_assert!(width >= source);
        if width == source {
            return a;
        }
        let node = self.nodes[a].clone();
        match node.op {
            HwOp::Const => self.konst(node.value, width),
            HwOp::Zext => self.zext(node.args[0], width),
            _ => self.intern(HwOp::Zext, width, vec![a], 0, ""),
        }
    }

    pub fn sext(&mut self, a: NodeId, width: u32) -> NodeId {
        let source = self.width(a);
        debug_assert!(width >= source);
        if width == source {
            return a;
        }
        let node = self.nodes[a].clone();
        match node.op {
            HwOp::Const => self
                .fold(HwOp::Sext, width, 0, &[a])
                .expect("a constant folds"),
            // A zero-extended value has a zero on top, so extending its sign
            // extends that zero.
            HwOp::Zext => self.zext(node.args[0], width),
            HwOp::Sext => self.sext(node.args[0], width),
            _ => self.intern(HwOp::Sext, width, vec![a], 0, ""),
        }
    }

    /// `a` at exactly `width` bits: its low bits, or zero-extended.
    pub fn resize(&mut self, a: NodeId, width: u32) -> NodeId {
        if width <= self.width(a) {
            self.slice(a, 0, width)
        } else {
            self.zext(a, width)
        }
    }

    pub fn concat(&mut self, hi: NodeId, lo: NodeId) -> NodeId {
        let (hi_width, lo_width) = (self.width(hi), self.width(lo));
        let width = hi_width + lo_width;
        if let Some(folded) = self.fold(HwOp::Concat, width, 0, &[hi, lo]) {
            return folded;
        }
        if self.as_const(hi) == Some(0) {
            return self.zext(lo, width);
        }
        // Two adjacent slices of one node are one slice.
        let (hi_node, lo_node) = (self.nodes[hi].clone(), self.nodes[lo].clone());
        if hi_node.op == HwOp::Slice
            && lo_node.op == HwOp::Slice
            && hi_node.args[0] == lo_node.args[0]
            && hi_node.value == lo_node.value + lo_width as u128
        {
            return self.slice(lo_node.args[0], lo_node.value as u32, width);
        }
        self.intern(HwOp::Concat, width, vec![hi, lo], 0, "")
    }

    pub fn rev(&mut self, a: NodeId) -> NodeId {
        let width = self.width(a);
        if width == 1 {
            return a;
        }
        if let Some(folded) = self.fold(HwOp::Rev, width, 0, &[a]) {
            return folded;
        }
        if self.nodes[a].op == HwOp::Rev {
            return self.nodes[a].args[0];
        }
        self.intern(HwOp::Rev, width, vec![a], 0, "")
    }

    pub fn not(&mut self, a: NodeId) -> NodeId {
        let width = self.width(a);
        if let Some(folded) = self.fold(HwOp::Not, width, 0, &[a]) {
            return folded;
        }
        if self.nodes[a].op == HwOp::Not {
            return self.nodes[a].args[0];
        }
        self.intern(HwOp::Not, width, vec![a], 0, "")
    }

    /// The bitwise operators, which share every identity but their constants.
    fn bitwise(&mut self, op: HwOp, a: NodeId, b: NodeId) -> NodeId {
        let width = self.width(a);
        debug_assert_eq!(width, self.width(b), "{op:?} over unequal widths");
        if let Some(folded) = self.fold(op, width, 0, &[a, b]) {
            return folded;
        }
        let (a, b) = (a.min(b), a.max(b));
        if a == b {
            return match op {
                HwOp::Xor => self.konst(0, width),
                _ => a,
            };
        }
        for (constant, other) in [(a, b), (b, a)] {
            let Some(value) = self.as_const(constant) else { continue };
            let ones = value == mask(width);
            match op {
                HwOp::And if value == 0 => return self.konst(0, width),
                HwOp::And if ones => return other,
                // A mask of low bits is a slice and a zero-extension: wires.
                // This is what makes `(sll i64 rs1 (and i64 rs2 0x3f))` a
                // six-stage shifter with no out-of-range detect.
                HwOp::And if (value + 1).is_power_of_two() => {
                    let low = self.slice(other, 0, (value + 1).trailing_zeros());
                    return self.zext(low, width);
                }
                HwOp::Or if value == 0 => return other,
                HwOp::Or if ones => return self.konst(value, width),
                HwOp::Xor if value == 0 => return other,
                HwOp::Xor if ones => return self.not(other),
                _ => {}
            }
        }
        // Two zero-extensions meet below their extension. Without this a
        // condition built from two comparisons -- `(and i64 (icmp_eq ..)
        // (icmp_eq ..))` -- would be a 64-bit gate over two bits.
        let inner = |graph: &Self, id: NodeId| -> Option<NodeId> {
            (graph.nodes[id].op == HwOp::Zext).then(|| graph.nodes[id].args[0])
        };
        match (inner(self, a), inner(self, b)) {
            (Some(x), Some(y)) if self.width(x) == self.width(y) => {
                let narrow = self.bitwise(op, x, y);
                return self.zext(narrow, width);
            }
            (Some(x), _) if op == HwOp::And => {
                let other = self.slice(b, 0, self.width(x));
                let narrow = self.bitwise(op, x, other);
                return self.zext(narrow, width);
            }
            (_, Some(y)) if op == HwOp::And => {
                let other = self.slice(a, 0, self.width(y));
                let narrow = self.bitwise(op, other, y);
                return self.zext(narrow, width);
            }
            _ => {}
        }
        self.intern(op, width, vec![a, b], 0, "")
    }

    pub fn and(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.bitwise(HwOp::And, a, b)
    }

    pub fn or(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.bitwise(HwOp::Or, a, b)
    }

    pub fn xor(&mut self, a: NodeId, b: NodeId) -> NodeId {
        self.bitwise(HwOp::Xor, a, b)
    }

    pub fn eq(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let width = self.width(a);
        debug_assert_eq!(width, self.width(b), "eq over unequal widths");
        if let Some(folded) = self.fold(HwOp::Eq, 1, 0, &[a, b]) {
            return folded;
        }
        let (a, b) = (a.min(b), a.max(b));
        if a == b {
            return self.konst(1, 1);
        }
        for (constant, other) in [(a, b), (b, a)] {
            let Some(value) = self.as_const(constant) else { continue };
            if width == 1 {
                return if value == 1 { other } else { self.not(other) };
            }
            // A zero-extended value equals a constant only below its extension.
            if self.nodes[other].op == HwOp::Zext {
                let inner = self.nodes[other].args[0];
                let inner_width = self.width(inner);
                if value > mask(inner_width) {
                    return self.konst(0, 1);
                }
                let narrow = self.konst(value, inner_width);
                return self.eq(inner, narrow);
            }
        }
        self.intern(HwOp::Eq, 1, vec![a, b], 0, "")
    }

    pub fn mux(&mut self, sel: NodeId, then: NodeId, otherwise: NodeId) -> NodeId {
        let width = self.width(then);
        debug_assert_eq!(self.width(sel), 1);
        debug_assert_eq!(width, self.width(otherwise), "mux over unequal widths");
        if let Some(value) = self.as_const(sel) {
            return if value == 1 { then } else { otherwise };
        }
        if then == otherwise {
            return then;
        }
        if width == 1 {
            match (self.as_const(then), self.as_const(otherwise)) {
                (Some(1), Some(0)) => return sel,
                (Some(0), Some(1)) => return self.not(sel),
                _ => {}
            }
        }
        if self.nodes[sel].op == HwOp::Not {
            let inner = self.nodes[sel].args[0];
            return self.mux(inner, otherwise, then);
        }
        // An arm that tests the same condition again already knows the answer.
        let (mut then, mut otherwise) = (then, otherwise);
        if self.nodes[then].op == HwOp::Mux && self.nodes[then].args[0] == sel {
            then = self.nodes[then].args[1];
        }
        if self.nodes[otherwise].op == HwOp::Mux && self.nodes[otherwise].args[0] == sel {
            otherwise = self.nodes[otherwise].args[2];
        }
        if then == otherwise {
            return then;
        }
        self.intern(HwOp::Mux, width, vec![sel, then, otherwise], 0, "")
    }

    pub fn addsub(&mut self, a: NodeId, b: NodeId, sub: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert_eq!(n, self.width(b), "addsub over unequal widths");
        debug_assert_eq!(self.width(sub), 1);
        if let Some(folded) = self.fold(HwOp::AddSub, n + 1, 0, &[a, b, sub]) {
            return folded;
        }
        let (mut a, mut b) = (a, b);
        if self.as_const(sub) == Some(0) {
            // Adding is commutative, and adding zero is a wire.
            (a, b) = (a.min(b), a.max(b));
            if self.as_const(a) == Some(0) {
                return self.zext(b, n + 1);
            }
            if self.as_const(b) == Some(0) {
                return self.zext(a, n + 1);
            }
        }
        self.intern(HwOp::AddSub, n + 1, vec![a, b, sub], 0, "")
    }

    pub fn add(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let n = self.width(a);
        // `(x + c1) + c2` is `x + (c1 + c2)`, both modulo 2^n. A constant step taken k
        // times -- an induction a loop's lanes advance one after another -- is then one
        // adder deep, not k adders in series.
        for (constant, other) in [(b, a), (a, b)] {
            let Some(c2) = self.as_const(constant) else { continue };
            if let Some((x, c1)) = self.plus_constant(other) {
                let c = self.konst(c1.wrapping_add(c2) & mask(n), n);
                return self.add(x, c);
            }
        }
        let zero = self.konst(0, 1);
        let sum = self.addsub(a, b, zero);
        self.slice(sum, 0, n)
    }

    /// `x + c` as [`add`](Self::add) builds it -- the low bits of an adder with a constant
    /// argument -- as `(x, c)`.
    fn plus_constant(&self, v: NodeId) -> Option<(NodeId, u128)> {
        let slice = &self.nodes[v];
        if slice.op != HwOp::Slice || slice.value != 0 {
            return None;
        }
        let sum = &self.nodes[slice.args[0]];
        if sum.op != HwOp::AddSub || self.as_const(sum.args[2]) != Some(0) || sum.width != slice.width + 1 {
            return None;
        }
        [(sum.args[0], sum.args[1]), (sum.args[1], sum.args[0])]
            .into_iter()
            .find_map(|(x, k)| self.as_const(k).map(|c| (x, c)))
    }

    /// `a - (a / b) * b` is the remainder the divider already has.
    ///
    /// RISC-V's `REM` is written that way, because the remainder AXIS defines
    /// is zero for a zero divisor and RISC-V's is the dividend. Lowered as
    /// written it is a divider, a multiplier and a subtractor; the identity
    /// holds for every nonzero divisor -- the overflowing `MIN / -1` included,
    /// where the wrapped quotient times -1 is `MIN` again and the difference
    /// is the zero the remainder is -- and for a zero divisor the quotient is
    /// zero, so the expression is `a`.
    fn remainder_of(&mut self, a: NodeId, b: NodeId) -> Option<NodeId> {
        let n = self.width(a);
        let product = self.nodes[b].clone();
        if product.op != HwOp::Mul {
            return None;
        }
        for (quotient, divisor) in [(product.args[0], product.args[1]), (product.args[1], product.args[0])] {
            let slice = self.nodes[quotient].clone();
            if slice.op != HwOp::Slice || slice.value != 0 {
                continue;
            }
            let pair = slice.args[0];
            let divide = self.nodes[pair].clone();
            if divide.op != HwOp::DivRem || divide.width != 2 * n {
                continue;
            }
            if divide.args[0] != a || divide.args[1] != divisor {
                continue;
            }
            let remainder = self.slice(pair, n, n);
            let zero = self.konst(0, n);
            let by_zero = self.eq(divisor, zero);
            return Some(self.mux(by_zero, a, remainder));
        }
        None
    }

    pub fn sub(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let n = self.width(a);
        if let Some(remainder) = self.remainder_of(a, b) {
            return remainder;
        }
        let one = self.konst(1, 1);
        let difference = self.addsub(a, b, one);
        self.slice(difference, 0, n)
    }

    /// `a < b`, unsigned: the subtractor's carry is clear.
    pub fn ult(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let n = self.width(a);
        let one = self.konst(1, 1);
        let difference = self.addsub(a, b, one);
        let carry = self.slice(difference, n, 1);
        self.not(carry)
    }

    /// `a < b`, signed. Where the signs differ the negative one is smaller;
    /// where they agree the difference cannot overflow and its sign decides.
    pub fn slt(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let n = self.width(a);
        let one = self.konst(1, 1);
        let difference = self.addsub(a, b, one);
        let sign = self.slice(difference, n - 1, 1);
        let a_sign = self.slice(a, n - 1, 1);
        let b_sign = self.slice(b, n - 1, 1);
        let differ = self.xor(a_sign, b_sign);
        self.mux(differ, a_sign, sign)
    }

    pub fn mul(&mut self, a: NodeId, b: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert_eq!(n, self.width(b), "mul over unequal widths");
        if let Some(folded) = self.fold(HwOp::Mul, n, 0, &[a, b]) {
            return folded;
        }
        let (a, b) = (a.min(b), a.max(b));
        for (constant, other) in [(a, b), (b, a)] {
            let Some(value) = self.as_const(constant) else { continue };
            if value == 0 {
                return self.konst(0, n);
            }
            if value.is_power_of_two() {
                // A multiply by a power of two is a left shift, which is wires.
                let shift = value.trailing_zeros();
                if shift == 0 {
                    return other;
                }
                let kept = self.slice(other, 0, n - shift);
                let zeros = self.konst(0, shift);
                return self.concat(kept, zeros);
            }
        }
        self.intern(HwOp::Mul, n, vec![a, b], 0, "")
    }

    pub fn mulwide(&mut self, a: NodeId, b: NodeId, sa: NodeId, sb: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert_eq!(n, self.width(b), "mulwide over unequal widths");
        if let Some(folded) = self.fold(HwOp::MulWide, 2 * n, 0, &[a, b, sa, sb]) {
            return folded;
        }
        let (a, b) = if sa == sb { (a.min(b), a.max(b)) } else { (a, b) };
        self.intern(HwOp::MulWide, 2 * n, vec![a, b, sa, sb], 0, "")
    }

    pub fn divrem(&mut self, a: NodeId, b: NodeId, signed: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert_eq!(n, self.width(b), "divrem over unequal widths");
        if let Some(folded) = self.fold(HwOp::DivRem, 2 * n, 0, &[a, b, signed]) {
            return folded;
        }
        self.intern(HwOp::DivRem, 2 * n, vec![a, b, signed], 0, "")
    }

    pub fn shr(&mut self, a: NodeId, amount: NodeId, fill: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert_eq!(self.width(fill), 1);
        if let Some(folded) = self.fold(HwOp::Shr, n, 0, &[a, amount, fill]) {
            return folded;
        }
        if let Some(value) = self.as_const(amount) {
            // A shift by a constant is a slice and a concat: wires.
            if value == 0 {
                return a;
            }
            if value >= n as u128 {
                return self.sext(fill, n);
            }
            let shift = value as u32;
            let kept = self.slice(a, shift, n - shift);
            let filled = self.sext(fill, shift);
            return self.concat(filled, kept);
        }
        // The amount is a number, so its zero-extension is the same amount.
        let amount = if self.nodes[amount].op == HwOp::Zext {
            self.nodes[amount].args[0]
        } else {
            amount
        };
        self.intern(HwOp::Shr, n, vec![a, amount, fill], 0, "")
    }

    /// `a << amount`: the right shifter, between two reversals.
    pub fn shl(&mut self, a: NodeId, amount: NodeId) -> NodeId {
        let zero = self.konst(0, 1);
        let reversed = self.rev(a);
        let shifted = self.shr(reversed, amount, zero);
        self.rev(shifted)
    }

    pub fn ror(&mut self, a: NodeId, amount: NodeId) -> NodeId {
        let n = self.width(a);
        debug_assert!(n.is_power_of_two() && n > 1);
        debug_assert_eq!(self.width(amount), ceil_log2(n));
        if let Some(folded) = self.fold(HwOp::Ror, n, 0, &[a, amount]) {
            return folded;
        }
        if let Some(value) = self.as_const(amount) {
            let shift = (value % n as u128) as u32;
            if shift == 0 {
                return a;
            }
            let low = self.slice(a, 0, shift);
            let high = self.slice(a, shift, n - shift);
            return self.concat(low, high);
        }
        self.intern(HwOp::Ror, n, vec![a, amount], 0, "")
    }

    pub fn clz(&mut self, a: NodeId) -> NodeId {
        let width = bit_length(self.width(a));
        if let Some(folded) = self.fold(HwOp::Clz, width, 0, &[a]) {
            return folded;
        }
        self.intern(HwOp::Clz, width, vec![a], 0, "")
    }

    pub fn cpop(&mut self, a: NodeId) -> NodeId {
        let width = bit_length(self.width(a));
        if let Some(folded) = self.fold(HwOp::Cpop, width, 0, &[a]) {
            return folded;
        }
        self.intern(HwOp::Cpop, width, vec![a], 0, "")
    }

    /// Make a node from its parts, through the builder for its operator -- so
    /// a node rebuilt over different arguments meets the same rewrites as one
    /// lowered from a description.
    pub fn make(&mut self, op: HwOp, width: u32, value: u128, args: &[NodeId]) -> NodeId {
        match op {
            HwOp::Input => unreachable!("an input is not rebuilt"),
            HwOp::Const => self.konst(value, width),
            HwOp::AddSub => self.addsub(args[0], args[1], args[2]),
            HwOp::Mul => self.mul(args[0], args[1]),
            HwOp::MulWide => self.mulwide(args[0], args[1], args[2], args[3]),
            HwOp::DivRem => self.divrem(args[0], args[1], args[2]),
            HwOp::Shr => self.shr(args[0], args[1], args[2]),
            HwOp::Ror => self.ror(args[0], args[1]),
            HwOp::Clz => self.clz(args[0]),
            HwOp::Cpop => self.cpop(args[0]),
            HwOp::Eq => self.eq(args[0], args[1]),
            HwOp::And => self.and(args[0], args[1]),
            HwOp::Or => self.or(args[0], args[1]),
            HwOp::Xor => self.xor(args[0], args[1]),
            HwOp::Not => self.not(args[0]),
            HwOp::Mux => self.mux(args[0], args[1], args[2]),
            HwOp::Zext => self.zext(args[0], width),
            HwOp::Sext => self.sext(args[0], width),
            HwOp::Slice => self.slice(args[0], value as u32, width),
            HwOp::Concat => self.concat(args[0], args[1]),
            HwOp::Rev => self.rev(args[0]),
        }
    }

    /// Every node `roots` depend on, themselves included, in ascending (so
    /// topological) order.
    pub fn cone(&self, roots: &[NodeId]) -> Vec<NodeId> {
        let mut seen = vec![false; self.nodes.len()];
        let mut stack: Vec<NodeId> = roots.to_vec();
        while let Some(id) = stack.pop() {
            if std::mem::replace(&mut seen[id], true) {
                continue;
            }
            stack.extend(self.nodes[id].args.iter().copied());
        }
        (0..self.nodes.len()).filter(|id| seen[*id]).collect()
    }

    /// The value at `root` for the given inputs, by name. An input reads the
    /// low bits of its name's value, which is how one port serves operands of
    /// different widths in a merged unit.
    pub fn eval(&self, root: NodeId, inputs: &HashMap<String, u128>) -> u128 {
        let mut values: HashMap<NodeId, u128> = HashMap::new();
        for id in self.cone(&[root]) {
            let node = &self.nodes[id];
            let value = if node.op == HwOp::Input {
                inputs.get(&node.name).copied().unwrap_or(0) & mask(node.width)
            } else {
                let args: Vec<(u128, u32)> = node
                    .args
                    .iter()
                    .map(|arg| (values[arg], self.nodes[*arg].width))
                    .collect();
                eval_op(node.op, node.width, node.value, &args)
            };
            values.insert(id, value);
        }
        values[&root]
    }

    /// One node's own area and delay under the cost model, every bit of it
    /// wanted.
    pub fn node_cost(&self, id: NodeId) -> (f64, f64) {
        self.node_cost_for(id, mask(self.nodes[id].width))
    }

    /// One node's area and delay when only the `demand`ed bits of its result
    /// are read.
    ///
    /// Two things are subtracted from the operator as a whole, because
    /// synthesis subtracts them: bits nothing reads, and bits that cannot
    /// change. A comparison is a subtractor of which only the carry is read,
    /// and is two thirds the size and half the depth; a mux with a literal
    /// arm is an AND; a mask is wires.
    pub fn node_cost_for(&self, id: NodeId, demand: u128) -> (f64, f64) {
        let node = &self.nodes[id];
        let live = demand & mask(node.width) & !self.known[id].any();
        if live == 0 {
            return (0.0, 0.0);
        }
        let count = |bits: u128| bits.count_ones() as f64;
        let constant = |index: usize| self.as_const(node.args[index]);
        let known = |index: usize| self.known[node.args[index]];
        let free = |index: usize| !known(index).any();
        let costed = |area: f64, delay: f64| if area > 0.0 { (area, delay) } else { (0.0, 0.0) };
        match node.op {
            // Wires.
            HwOp::Input | HwOp::Const | HwOp::Zext | HwOp::Sext | HwOp::Slice | HwOp::Concat
            | HwOp::Rev => (0.0, 0.0),
            HwOp::Not => (GE_NOT * count(live), DELAY_NOT),
            // A bit with a known operand is the other operand or a constant.
            HwOp::And | HwOp::Or => costed(GE_AND * count(live & free(0) & free(1)), DELAY_AND),
            HwOp::Xor => {
                let gates = live & free(0) & free(1);
                let inverted = live & (known(0).ones & free(1) | known(1).ones & free(0));
                if gates != 0 {
                    (GE_XOR * count(gates) + GE_NOT * count(inverted), DELAY_XOR)
                } else {
                    costed(GE_NOT * count(inverted), DELAY_NOT)
                }
            }
            HwOp::Mux => {
                let both = live & free(1) & free(2);
                let one = live & (free(1) ^ free(2));
                // A mux that reads a mux is a level of a tree, and a tree is
                // mapped to four-input cells and AND-OR forms, not built
                // from two-input muxes one by one.
                let nested = node.args[1..]
                    .iter()
                    .filter(|arg| self.nodes[**arg].op == HwOp::Mux)
                    .count() as f64;
                let cell = GE_MUX - GE_MUX_NESTED * nested;
                // What this mux adds to its tree is the values it brings in.
                // Arms that are functions of the same bits of the same values
                // make one function of those bits, not a mux apiece.
                let fresh = match &self.support[id] {
                    Some(all) => {
                        let brought = |arg: NodeId| match &self.support[arg] {
                            Some(list) if self.nodes[arg].op == HwOp::Mux => list.len() as f64,
                            _ => 1.0,
                        };
                        (all.len() as f64 + 1.0 - brought(node.args[1]) - brought(node.args[2]))
                            .clamp(MUX_REPEATED, 1.0)
                    }
                    None => 1.0,
                };
                if both != 0 {
                    ((cell * count(both) + GE_AND * count(one)) * fresh, DELAY_MUX)
                } else {
                    costed(GE_AND * count(one) * fresh, DELAY_AND)
                }
            }
            HwOp::Eq => {
                let n = mask(self.width(node.args[0]));
                let compared = count(n & free(0) & free(1));
                let against = count(n & (free(0) ^ free(1)));
                let wide = (compared + against).max(1.0).log2();
                if compared > 0.0 {
                    (EQ_BIT * compared + EQ_CONST_BIT * against, wide + 1.0)
                } else {
                    costed(EQ_CONST_BIT * against, 0.5 * wide + 2.5)
                }
            }
            HwOp::AddSub => self.addsub_cost_for(node, live),
            HwOp::Mul => self.multiplier_cost_for(node, live),
            HwOp::MulWide => {
                let unsigned = constant(2) == Some(0) && constant(3) == Some(0);
                wide_multiplier_cost(node.width / 2, !unsigned)
            }
            HwOp::DivRem => divider_cost(node.width / 2, constant(2) != Some(0)),
            HwOp::Shr => shifter_cost(node.width, self.width(node.args[1])),
            HwOp::Ror => rotator_cost(node.width),
            HwOp::Clz => leading_zeros_cost(self.width(node.args[0])),
            HwOp::Cpop => population_cost(self.width(node.args[0])),
        }
    }

    /// An adder, bit by bit. A bit whose sum is read is a full cell; one
    /// below the lowest bit read still has to make its carry and is a
    /// comparator's cell; one with a known operand is half of either.
    fn addsub_cost_for(&self, node: &HwNode, live: u128) -> (f64, f64) {
        let n = node.width - 1;
        let sub = self.as_const(node.args[2]);
        let a = self.known[node.args[0]];
        // Subtracting on a run-time signal, a known bit of `b` reaches the
        // adder as that signal or its inverse: no XOR, but not a constant.
        let b = if sub.is_some() { self.known[node.args[1]] } else { KnownBits::default() };
        let b_free = !self.known[node.args[1]].any();
        let top = 127 - live.leading_zeros();
        let range = (top + 1).min(n);
        // With no carry in, the low bits where an operand is zero are wires.
        let mut first = 0;
        if sub == Some(0) {
            while first < range && (a.zeros | b.zeros) >> first & 1 == 1 {
                first += 1;
            }
        }
        // The bits of an operand above its sign extension are one signal.
        let repeated = |arg: NodeId| -> u128 {
            let source = &self.nodes[arg];
            if source.op == HwOp::Sext { !mask(self.width(source.args[0])) } else { 0 }
        };
        let repeats = repeated(node.args[0]) | repeated(node.args[1]);
        let (mut area, mut widest) = (0.0, 0);
        for bit in first..range {
            let unknown = (!a.any() >> bit & 1) + (!b.any() >> bit & 1);
            let read = live >> bit & 1 == 1;
            area += match (unknown, read) {
                (2, true) if repeats >> bit & 1 == 1 => GE_REPEAT_ADDER_BIT,
                (2, false) if repeats >> bit & 1 == 1 => GE_REPEAT_CARRY_BIT,
                (2, true) => GE_ADDER_BIT,
                (2, false) => GE_CARRY_BIT,
                (1, true) => GE_HALF_ADDER_BIT,
                (1, false) => GE_HALF_CARRY_BIT,
                (_, true) => GE_NOT,
                (_, false) => 0.3,
            };
            widest = widest.max(unknown);
            if b_free >> bit & 1 == 1 {
                area += match sub {
                    None => GE_SUB_XOR_BIT,
                    Some(1) if read => GE_NOT,
                    _ => 0.0,
                };
            }
        }
        let width = range - first;
        if width == 0 {
            return (0.0, 0.0);
        }
        // The carry into the lowest bit read comes up a comparator's tree;
        // only the bits read from there need an adder's.
        let carry = |bits: u32| if bits == 0 { 0.0 } else { 1.5 * lg(bits) + 1.5 };
        let reads_sum = live & mask(n) != 0;
        let mut delay = if reads_sum {
            let lowest = (live & mask(n)).trailing_zeros().max(first);
            adder_cost(range - lowest).1.max(carry(lowest - first) + adder_cost(1).1)
        } else {
            carry(width)
        };
        if widest < 2 {
            delay *= 0.6;
        }
        delay += match sub {
            None => 1.0,
            Some(1) if reads_sum => 2.0,
            _ => 0.0,
        };
        (area, delay)
    }

    /// A multiplier by its partial products: one for every pair of operand
    /// bits that can both be set and whose weight is below the highest bit
    /// read. An operand zero-extended from half the width makes a quarter of
    /// them, and a constant makes one row per set bit.
    fn multiplier_cost_for(&self, node: &HwNode, live: u128) -> (f64, f64) {
        let width = 128 - live.leading_zeros();
        let a = !self.known[node.args[0]].zeros & mask(width.min(self.width(node.args[0])));
        let b = !self.known[node.args[1]].zeros & mask(width.min(self.width(node.args[1])));
        let mut products = 0u32;
        for bit in 0..width {
            if a >> bit & 1 == 1 {
                products += (b & mask(width - bit)).count_ones();
            }
        }
        let longest = (128 - a.leading_zeros()).max(128 - b.leading_zeros());
        let area = GE_PRODUCT_BIT * products as f64 - GE_PRODUCT_EDGE * longest as f64;
        if area <= 0.0 {
            return (0.0, 0.0); // by a power of two: a shift
        }
        // Both words read, the final adder is twice as wide.
        let both_words = width > longest;
        (area, multiplier_delay(longest, both_words))
    }

    /// The bits of each node of `roots`' cone that something reads. A root is
    /// read whole; below it, an operator asks its arguments only for what its
    /// own read bits depend on.
    pub fn demand(&self, roots: &[NodeId]) -> HashMap<NodeId, u128> {
        let cone = self.cone(roots);
        let mut demand: HashMap<NodeId, u128> = cone.iter().map(|id| (*id, 0)).collect();
        for root in roots {
            demand.insert(*root, mask(self.width(*root)));
        }
        for id in cone.into_iter().rev() {
            let node = &self.nodes[id];
            let live = demand[&id] & !self.known[id].any();
            if live == 0 {
                continue;
            }
            let width = |index: usize| self.width(node.args[index]);
            let known = |index: usize| self.known[node.args[index]];
            let top = 128 - live.leading_zeros();
            let wanted: Vec<u128> = match node.op {
                HwOp::Input | HwOp::Const => vec![],
                HwOp::Zext => vec![live],
                HwOp::Sext => {
                    let from = width(0);
                    let sign = if live & !mask(from) != 0 { 1u128 << (from - 1) } else { 0 };
                    vec![live | sign]
                }
                HwOp::Slice => vec![live << node.value],
                HwOp::Concat => vec![live >> width(1), live],
                HwOp::Not | HwOp::Xor => vec![live; node.args.len()],
                // Where the other operand decides the bit, this one is not read.
                HwOp::And => vec![live & !known(1).zeros, live & !known(0).zeros],
                HwOp::Or => vec![live & !known(1).ones, live & !known(0).ones],
                HwOp::Mux => vec![1, live, live],
                // A carry only travels up.
                HwOp::AddSub => vec![mask(top), mask(top), 1],
                HwOp::Mul => vec![mask(top), mask(top)],
                _ => vec![u128::MAX; node.args.len()],
            };
            for (arg, bits) in node.args.iter().zip(wanted) {
                *demand.get_mut(arg).unwrap() |= bits & mask(self.width(*arg));
            }
        }
        demand
    }

    /// Each node of `roots`' cone with its area and delay, costed for the
    /// bits of it the cone reads.
    fn cone_costs(&self, roots: &[NodeId]) -> Vec<(NodeId, f64, f64)> {
        let demand = self.demand(roots);
        // Shifters of one value by one amount are one tree of muxes with
        // different bits shifted in -- a logical shift, an arithmetic one and
        // a rotate differ only at the edge -- and synthesis builds the tree
        // once whether or not anything was merged.
        let mut shifted: std::collections::HashSet<(NodeId, NodeId)> = Default::default();
        self.cone(roots)
            .into_iter()
            .map(|id| {
                let node = &self.nodes[id];
                let (mut area, delay) = self.node_cost_for(id, demand[&id]);
                if matches!(node.op, HwOp::Shr | HwOp::Ror)
                    && !shifted.insert((node.args[0], self.low_bits_of(node.args[1])))
                {
                    area *= SHIFTER_AGAIN;
                }
                (id, area, delay)
            })
            .collect()
    }

    /// The value `id` is the low bits of, through any number of truncations
    /// and zero-extensions: five bits of an amount and all of it are the
    /// same rows of a shifter.
    fn low_bits_of(&self, mut id: NodeId) -> NodeId {
        loop {
            let node = &self.nodes[id];
            match node.op {
                HwOp::Zext => id = node.args[0],
                HwOp::Slice if node.value == 0 => id = node.args[0],
                _ => return id,
            }
        }
    }

    /// Where a cone's area is: the total of each kind of operator in it.
    pub fn cone_area_by_operator(&self, roots: &[NodeId]) -> Vec<(String, f64)> {
        let mut by: std::collections::BTreeMap<String, f64> = Default::default();
        for (id, area, _) in self.cone_costs(roots) {
            if area > 0.0 {
                *by.entry(format!("{:?}", self.nodes[id].op).to_lowercase()).or_default() += area;
            }
        }
        by.into_iter().collect()
    }

    /// Total area of the cone under `roots`, and its longest path.
    pub fn cone_cost(&self, roots: &[NodeId]) -> (f64, f64) {
        let mut arrival: HashMap<NodeId, f64> = HashMap::new();
        let mut area = 0.0;
        let mut depth: f64 = 0.0;
        for (id, node_area, delay) in self.cone_costs(roots) {
            let ready = self.nodes[id]
                .args
                .iter()
                .map(|arg| arrival[arg])
                .fold(0.0, f64::max);
            area += node_area;
            arrival.insert(id, ready + delay);
            depth = depth.max(ready + delay);
        }
        (area, depth)
    }

    /// `root` with every input read through its port: an input narrower than
    /// `ports` says its name is becomes the low bits of the port-wide one.
    ///
    /// Two instructions that read different widths of one operand name two
    /// inputs, and nothing that compares nodes can see they are one wire.
    /// Read this way they are, and what both compute from it is one node.
    pub fn through_ports(&mut self, root: NodeId, ports: &HashMap<String, u32>,
                         done: &mut HashMap<NodeId, NodeId>) -> NodeId {
        if let Some(known) = done.get(&root) {
            return *known;
        }
        let node = self.nodes[root].clone();
        let out = match node.op {
            HwOp::Input => match ports.get(&node.name) {
                Some(width) if *width > node.width => {
                    let port = self.input(&node.name, *width);
                    self.slice(port, 0, node.width)
                }
                _ => root,
            },
            _ if node.args.is_empty() => root,
            _ => {
                let args: Vec<NodeId> =
                    node.args.iter().map(|arg| self.through_ports(*arg, ports, done)).collect();
                if args == node.args { root } else { self.make(node.op, node.width, node.value, &args) }
            }
        };
        done.insert(root, out);
        out
    }
}

/// Base-two logarithm of a width, for the fitted shapes: at the widths the
/// fits were made on it is the whole number `ceil_log2` gives, and between
/// them it does not jump.
fn lg(n: u32) -> f64 {
    (n.max(1) as f64).log2()
}

/// A prefix adder: linear in cells, logarithmic in depth.
pub fn adder_cost(n: u32) -> (f64, f64) {
    (GE_ADDER_BIT * n as f64, (3.2 * lg(n) + 3.3).max(DELAY_XOR))
}

/// An adder that may subtract. `sub` is the subtract input when it is a
/// constant: nothing more for an add, a row of inverters folded into the
/// first level for a subtract, a row of XORs when it is decided at run time.
pub fn addsub_cost(n: u32, sub: Option<bool>) -> (f64, f64) {
    let (area, delay) = adder_cost(n);
    match sub {
        Some(false) => (area, delay),
        Some(true) => (area + GE_NOT * n as f64, delay + 2.0),
        None => (area + GE_SUB_XOR_BIT * n as f64, delay + 1.0),
    }
}

/// Equality: an XOR row and an AND tree; against a constant, the tree alone.
pub fn equality_cost(n: u32, constant: bool) -> (f64, f64) {
    if constant {
        (EQ_CONST_BIT * n as f64, 0.5 * lg(n) + 2.5)
    } else {
        (EQ_BIT * n as f64, lg(n) + 1.0)
    }
}

/// A multiplier's depth: a tree over the partial products, then an adder --
/// twice as wide when both words of the product are read.
fn multiplier_delay(n: u32, both_words: bool) -> f64 {
    let depth = if both_words { 15.0 * lg(n) - 20.0 } else { 14.0 * lg(n) - 23.0 };
    depth.max(DELAY_AND)
}

/// The low word of an `n` by `n` product: half a square of partial products.
///
/// `wide` is kept for the callers that weigh one multiplier against another
/// by class; a product with both words is [`wide_multiplier_cost`].
pub fn multiplier_cost(n: u32, wide: bool) -> (f64, f64) {
    if wide {
        return wide_multiplier_cost(n, true);
    }
    let products = (n as f64) * (n as f64 + 1.0) / 2.0;
    let area = GE_PRODUCT_BIT * products - GE_PRODUCT_EDGE * n as f64;
    (area.max(GE_AND), multiplier_delay(n, false))
}

/// Both words of an `n` by `n` product.
///
/// ⚠️ Signed costs more than a sign should: the netlist extends both operands
/// to `2n` bits and takes the low `2n` of that product, and synthesis recovers
/// most of the difference but not all of it. A Baugh-Wooley array would cost
/// what the unsigned one does; this is what is emitted.
pub fn wide_multiplier_cost(n: u32, signed: bool) -> (f64, f64) {
    let w = n as f64;
    let area = GE_PRODUCT_BIT * w * w - GE_PRODUCT_EDGE * w
        + if signed { 0.6 * w * w + 16.0 * w } else { 0.0 };
    (area.max(GE_AND), multiplier_delay(n, true))
}

/// A restoring divider, unrolled: a subtractor and a mux per quotient bit,
/// and three negations around it when it divides signed.
///
/// ⚠️ Nobody builds this combinationally at 64 bits. The number is what the
/// emitted netlist is, which is what the model is for; a sequential divider is
/// a later stage and will be costed as one.
pub fn divider_cost(n: u32, signed: bool) -> (f64, f64) {
    let (w, lg) = (n as f64, lg(n));
    let area = w * w * (4.0 + 0.9 * lg) + if signed { 30.0 * w } else { 0.0 };
    let delay = w * (3.5 * lg - 0.5).max(DELAY_MUX) + if signed { 12.0 } else { 0.0 };
    (area, delay)
}

/// A logarithmic shifter: a mux row per amount bit that can matter, and an
/// out-of-range detect when the amount can exceed the width.
pub fn shifter_cost(n: u32, amount_bits: u32) -> (f64, f64) {
    let stages = amount_bits.min(ceil_log2(n));
    let over = amount_bits > stages;
    (
        GE_MUX_ROW * n as f64 * stages as f64 + if over { 0.9 * n as f64 } else { 0.0 },
        DELAY_MUX * stages as f64 + if over { 1.5 } else { 0.0 },
    )
}

/// A rotator: a mux row per amount bit.
pub fn rotator_cost(n: u32) -> (f64, f64) {
    (3.05 * n as f64 * lg(n), 2.5 * lg(n))
}

/// Count of leading zeros.
///
/// ⚠️ The depth is linear in the width, not logarithmic: the netlist is a
/// priority chain of muxes, the highest set bit applied last, and synthesis
/// does not turn it into a tree.
pub fn leading_zeros_cost(n: u32) -> (f64, f64) {
    (2.8 * n as f64, 0.47 * n as f64 + 1.2)
}

/// Population count: a tree of adders that widen as they go up.
pub fn population_cost(n: u32) -> (f64, f64) {
    (n as f64 * (4.3 + 0.8 * lg(n)), (9.0 * lg(n) - 14.0).max(DELAY_XOR))
}

/// What the model says each operator costs alone, at the widths it was fitted
/// on: `(operator, width, area, delay)`. Published in `emit-hw-json` so the
/// calibration compares synthesis with the model that ships, not with a copy
/// of its formulas.
pub fn operator_costs() -> Vec<(&'static str, u32, f64, f64)> {
    let mut table = Vec::new();
    for n in [8u32, 16, 32, 64] {
        let w = n as f64;
        let bits = ceil_log2(n);
        let mut row = |name: &'static str, (area, delay): (f64, f64)| table.push((name, n, area, delay));
        row("not", (GE_NOT * w, DELAY_NOT));
        row("and", (GE_AND * w, DELAY_AND));
        row("xor", (GE_XOR * w, DELAY_XOR));
        row("mux", (GE_MUX * w, DELAY_MUX));
        row("eq", equality_cost(n, false));
        row("eq_const", equality_cost(n, true));
        row("add", addsub_cost(n, Some(false)));
        row("sub", addsub_cost(n, Some(true)));
        row("addsub", addsub_cost(n, None));
        row("mul", multiplier_cost(n, false));
        row("mulwide", wide_multiplier_cost(n, true));
        row("mulwide_unsigned", wide_multiplier_cost(n, false));
        row("divrem", divider_cost(n, true));
        row("divrem_unsigned", divider_cost(n, false));
        row("shift", shifter_cost(n, bits));
        row("shift_short", shifter_cost(n, bits - 2));
        row("shift_over", shifter_cost(n, bits + 2));
        row("rotate", rotator_cost(n));
        row("clz", leading_zeros_cost(n));
        row("cpop", population_cost(n));
    }
    table
}

/// The typed IR, hash-consed. `let` bindings are inlined by [`ir::lower`], so
/// one bound value appears as many equal subtrees; interning them is what lets
/// the demand pass see that they are one value wanted at several widths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SemNode {
    Sym(String),
    Int(u128),
    App { op: Op, width: u32, args: Vec<usize> },
    Ext { op: Op, width: u32, from_bits: u32, arg: usize },
    Call { name: String, width: u32, args: Vec<(u32, usize)> },
}

#[derive(Default)]
struct SemDag {
    nodes: Vec<SemNode>,
    index: HashMap<SemNode, usize>,
}

impl SemDag {
    fn intern(&mut self, sem: &Sem) -> usize {
        let node = match sem {
            Sem::Sym(name) => SemNode::Sym(name.clone()),
            // The ambient width a literal was parsed at is not part of what it
            // means here: it is reduced to whatever width is demanded of it.
            Sem::Int { value, .. } => SemNode::Int(*value),
            Sem::App { op, width, args } => SemNode::App {
                op: *op,
                width: *width,
                args: args.iter().map(|arg| self.intern(arg)).collect(),
            },
            Sem::Ext { op, width, from_bits, arg } => SemNode::Ext {
                op: *op,
                width: *width,
                from_bits: *from_bits,
                arg: self.intern(arg),
            },
            Sem::Call { name, width, args } => SemNode::Call {
                name: name.clone(),
                width: *width,
                args: args.iter().map(|(param, arg)| (*param, self.intern(arg))).collect(),
            },
        };
        if let Some(id) = self.index.get(&node) {
            return *id;
        }
        let id = self.nodes.len();
        self.nodes.push(node.clone());
        self.index.insert(node, id);
        id
    }
}

/// A `deffun`'s reference body, where it has one.
///
/// An intrinsic may name an implementation and state no body, and then there
/// is nothing to inline. This reads the body through a trait so the lowering
/// is the same code whether a function's body is always present or optional.
trait ReferenceBody {
    fn reference(&self) -> Option<&SemanticExpr>;
}

impl ReferenceBody for SemanticExpr {
    fn reference(&self) -> Option<&SemanticExpr> {
        Some(self)
    }
}

impl ReferenceBody for Option<SemanticExpr> {
    fn reference(&self) -> Option<&SemanticExpr> {
        self.as_ref()
    }
}

/// How deep `deffun` calls may nest before the lowering gives up. A
/// description's functions are not recursive, so this is a guard and not a
/// limit anyone should meet.
const MAX_CALL_DEPTH: u32 = 32;

struct Scope<'a> {
    graph: &'a mut HwGraph,
    functions: &'a HashMap<String, Function>,
    env: &'a HashMap<String, NodeId>,
    dag: SemDag,
    /// The widest each expression is ever asked for.
    demand: HashMap<usize, u32>,
    memo: HashMap<(usize, u32), NodeId>,
    /// The first pass records demands; the second lowers each expression once,
    /// at its widest, and slices that for every narrower request.
    recording: bool,
    depth: u32,
}

impl Scope<'_> {
    fn lower(&mut self, id: usize, n: u32) -> Result<NodeId, String> {
        if n == 0 || n > MAX_WIDTH {
            return Err(format!("a value wider than {MAX_WIDTH} bits"));
        }
        if let Some(node) = self.memo.get(&(id, n)) {
            return Ok(*node);
        }
        let node = if self.recording {
            let widest = self.demand.entry(id).or_insert(0);
            *widest = (*widest).max(n);
            self.lower_node(id, n)?
        } else {
            let widest = self.demand.get(&id).copied().unwrap_or(n);
            if widest > n {
                let wide = self.lower(id, widest)?;
                self.graph.slice(wide, 0, n)
            } else {
                self.lower_node(id, n)?
            }
        };
        self.memo.insert((id, n), node);
        Ok(node)
    }

    /// An operator that masks its result to `width`: `value` is that result,
    /// and anything demanded above it is zero.
    fn masked(&mut self, value: NodeId, n: u32) -> NodeId {
        self.graph.resize(value, n)
    }

    /// An `n`-bit node congruent, modulo `2^n`, to what the golden model
    /// computes for this expression.
    fn lower_node(&mut self, id: usize, n: u32) -> Result<NodeId, String> {
        match self.dag.nodes[id].clone() {
            SemNode::Sym(name) => {
                let Some(node) = self.env.get(&name).copied() else {
                    return Err(format!("reads `{name}`, which is not an operand"));
                };
                Ok(self.graph.resize(node, n))
            }
            SemNode::Int(value) => Ok(self.graph.konst(value, n)),
            SemNode::Ext { op, width, from_bits, arg } => {
                if from_bits == 0 {
                    return Err("an extension from zero bits".to_string());
                }
                match op {
                    // `_mask(_signed(v, from), width)`. Below `from` the sign
                    // extension has not started, so the value's own low bits
                    // are the answer; above `width` the mask has cleared it.
                    Op::Sext => {
                        if from_bits >= width {
                            let value = self.lower(arg, n.min(width))?;
                            Ok(self.masked(value, n))
                        } else if n <= from_bits {
                            self.lower(arg, n)
                        } else {
                            let value = self.lower(arg, from_bits)?;
                            let extended = self.graph.sext(value, n.min(width));
                            Ok(self.masked(extended, n))
                        }
                    }
                    Op::Zext => {
                        let kept = from_bits.min(width);
                        if n <= kept {
                            self.lower(arg, n)
                        } else {
                            let value = self.lower(arg, kept)?;
                            Ok(self.masked(value, n))
                        }
                    }
                    other => Err(no_circuit(other)),
                }
            }
            SemNode::App { op, width, args } => self.lower_app(op, width, &args, n),
            SemNode::Call { name, width, args } => {
                let Some(function) = self.functions.get(&name) else {
                    return Err(format!("calls `{name}`, which is not defined"));
                };
                let Some(body) = function.body.reference() else {
                    return Err(format!("intrinsic `{name}` has no reference body"));
                };
                if function.params.len() != args.len() {
                    return Err(format!("calls `{name}` with the wrong number of arguments"));
                }
                if self.depth >= MAX_CALL_DEPTH {
                    return Err(format!("`{name}` nests calls too deeply to inline"));
                }
                // Hardware has no calls: the body is inlined, over arguments
                // each read at its parameter's width, and masked to the
                // result type as every software backend masks it.
                let mut env = HashMap::new();
                for ((param, param_width), (_, arg)) in function.params.iter().zip(&args) {
                    env.insert(param.clone(), self.lower(*arg, *param_width)?);
                }
                let body = with_references(body, self.functions);
                let sem = ir::lower(&body, width).map_err(|error| error.to_string())?;
                let value = lower_expr_at(
                    self.graph,
                    self.functions,
                    &sem,
                    &env,
                    n.min(width),
                    self.depth + 1,
                )?;
                Ok(self.masked(value, n))
            }
        }
    }

    fn lower_app(&mut self, op: Op, width: u32, args: &[usize], n: u32) -> Result<NodeId, String> {
        if width == 0 || width > MAX_WIDTH {
            return Err(format!("a value wider than {MAX_WIDTH} bits"));
        }
        // Ordering is decided by a subtractor's carry, one bit above the
        // operands, and the graph holds nothing wider than `MAX_WIDTH`.
        let orders = matches!(
            op,
            Op::IcmpSlt | Op::IcmpSge | Op::IcmpUlt | Op::IcmpUge | Op::MinS | Op::MaxS
                | Op::MinU | Op::MaxU
        ) || (op == Op::Shl && n > width);
        if orders && width >= MAX_WIDTH {
            return Err(format!("a comparison {MAX_WIDTH} bits wide"));
        }
        match op {
            // Ring operators: the low `n` bits of the result depend only on
            // the low `n` bits of the arguments, and the golden model does not
            // mask them, so they are computed at the demanded width whatever
            // the type atom says.
            Op::Add | Op::Sub => {
                if n >= MAX_WIDTH {
                    return Err(format!("an adder {MAX_WIDTH} bits wide"));
                }
                let mut acc = self.lower(args[0], n)?;
                for arg in &args[1..] {
                    let value = self.lower(*arg, n)?;
                    acc = if op == Op::Add {
                        self.graph.add(acc, value)
                    } else {
                        self.graph.sub(acc, value)
                    };
                }
                Ok(acc)
            }
            Op::Mul | Op::And | Op::Or | Op::Xor => {
                let mut acc = self.lower(args[0], n)?;
                for arg in &args[1..] {
                    let value = self.lower(*arg, n)?;
                    acc = match op {
                        Op::Mul => self.graph.mul(acc, value),
                        Op::And => self.graph.and(acc, value),
                        Op::Or => self.graph.or(acc, value),
                        _ => self.graph.xor(acc, value),
                    };
                }
                Ok(acc)
            }
            Op::Not => {
                let value = self.lower(args[0], n.min(width))?;
                let inverted = self.graph.not(value);
                Ok(self.masked(inverted, n))
            }
            Op::Udiv | Op::Urem => {
                let pair = self.divide(width, args, false)?;
                let lo = if op == Op::Udiv { 0 } else { width };
                let value = self.graph.slice(pair, lo, width);
                Ok(self.masked(value, n))
            }
            // The signed quotient is NOT masked by the golden model: it is a
            // negative integer, so above `width` it is sign-extended -- except
            // for the one quotient that overflows, `MIN / -1`, which is
            // positive. Dividing one bit wider makes that case ordinary.
            Op::Sdiv => {
                if n <= width {
                    let pair = self.divide(width, args, true)?;
                    Ok(self.graph.slice(pair, 0, n))
                } else {
                    let wider = width + 1;
                    if wider > 64 {
                        return Err("a divider wider than 64 bits".to_string());
                    }
                    let a = self.lower(args[0], width)?;
                    let b = self.lower(args[1], width)?;
                    let (a, b) = (self.graph.sext(a, wider), self.graph.sext(b, wider));
                    let one = self.graph.konst(1, 1);
                    let pair = self.graph.divrem(a, b, one);
                    let quotient = self.graph.slice(pair, 0, wider);
                    Ok(self.graph.sext(quotient, n))
                }
            }
            Op::Srem => {
                let pair = self.divide(width, args, true)?;
                let remainder = self.graph.slice(pair, width, width);
                if n <= width {
                    Ok(self.graph.slice(remainder, 0, n))
                } else {
                    Ok(self.graph.sext(remainder, n))
                }
            }
            // `0 if amount >= width else value << amount`, the value unmasked.
            // A left shift's low `n` bits are zero once the amount reaches
            // `n`, so below the type's width the range check is free; above
            // it, it has to be built.
            Op::Shl => {
                let amount = self.lower(args[1], width)?;
                let value = self.lower(args[0], n)?;
                let shifted = self.graph.shl(value, amount);
                if n <= width {
                    return Ok(shifted);
                }
                let limit = self.graph.konst(width as u128, width);
                let in_range = self.graph.ult(amount, limit);
                let zero = self.graph.konst(0, n);
                Ok(self.graph.mux(in_range, shifted, zero))
            }
            Op::Lshr | Op::Ashr => {
                let amount = self.lower(args[1], width)?;
                let value = self.lower(args[0], width)?;
                let fill = if op == Op::Ashr {
                    self.graph.slice(value, width - 1, 1)
                } else {
                    self.graph.konst(0, 1)
                };
                let shifted = self.graph.shr(value, amount, fill);
                Ok(self.masked(shifted, n))
            }
            // The golden model reduces the amount modulo the width from an
            // unbounded integer, which the amount's low bits equal only when
            // the width is a power of two.
            Op::Rol | Op::Ror => {
                if !width.is_power_of_two() {
                    return Err("a rotate at a width that is not a power of two".to_string());
                }
                let value = self.lower(args[0], width)?;
                if width == 1 {
                    return Ok(self.masked(value, n));
                }
                let amount = self.lower(args[1], ceil_log2(width))?;
                let rotated = if op == Op::Ror {
                    self.graph.ror(value, amount)
                } else {
                    let reversed = self.graph.rev(value);
                    let rotated = self.graph.ror(reversed, amount);
                    self.graph.rev(rotated)
                };
                Ok(self.masked(rotated, n))
            }
            Op::Clz | Op::Ctz | Op::Cpop => {
                let value = self.lower(args[0], width)?;
                let count = match op {
                    Op::Clz => self.graph.clz(value),
                    // Trailing zeros are the reversed value's leading ones.
                    Op::Ctz => {
                        let reversed = self.graph.rev(value);
                        self.graph.clz(reversed)
                    }
                    _ => self.graph.cpop(value),
                };
                Ok(self.masked(count, n))
            }
            Op::MinS | Op::MaxS | Op::MinU | Op::MaxU => {
                let a = self.lower(args[0], width)?;
                let b = self.lower(args[1], width)?;
                let signed = matches!(op, Op::MinS | Op::MaxS);
                // `min` keeps the left when it is smaller, `max` when the
                // right is: one comparison with its operands swapped.
                let (x, y) = if matches!(op, Op::MinS | Op::MinU) { (a, b) } else { (b, a) };
                let keep_left = if signed { self.graph.slt(x, y) } else { self.graph.ult(x, y) };
                let chosen = self.graph.mux(keep_left, a, b);
                Ok(self.masked(chosen, n))
            }
            // The condition is masked to the type's width; the arms are not.
            Op::Select => {
                let condition = self.lower(args[0], width)?;
                let zero = self.graph.konst(0, width);
                let is_zero = self.graph.eq(condition, zero);
                let then = self.lower(args[1], n)?;
                let otherwise = self.lower(args[2], n)?;
                Ok(self.graph.mux(is_zero, otherwise, then))
            }
            Op::IcmpEq | Op::IcmpNe | Op::IcmpSlt | Op::IcmpSge | Op::IcmpUlt | Op::IcmpUge => {
                let a = self.lower(args[0], width)?;
                let b = self.lower(args[1], width)?;
                let bit = match op {
                    Op::IcmpEq | Op::IcmpNe => self.graph.eq(a, b),
                    Op::IcmpSlt | Op::IcmpSge => self.graph.slt(a, b),
                    _ => self.graph.ult(a, b),
                };
                let bit = if matches!(op, Op::IcmpNe | Op::IcmpSge | Op::IcmpUge) {
                    self.graph.not(bit)
                } else {
                    bit
                };
                Ok(self.masked(bit, n))
            }
            Op::Mulh | Op::Mulhu | Op::Mulhsu => {
                if width > 64 {
                    return Err("a high-half multiply wider than 64 bits".to_string());
                }
                let a = self.lower(args[0], width)?;
                let b = self.lower(args[1], width)?;
                let (sa, sb) = match op {
                    Op::Mulh => (1, 1),
                    Op::Mulhu => (0, 0),
                    _ => (1, 0),
                };
                let (sa, sb) = (self.graph.konst(sa, 1), self.graph.konst(sb, 1));
                let product = self.graph.mulwide(a, b, sa, sb);
                let high = self.graph.slice(product, width, width);
                Ok(self.masked(high, n))
            }
            // `(1 << min(count, width)) - 1`: every bit a left shift of all
            // ones leaves clear, and a shift at or past the width leaves
            // them all clear.
            Op::Ones => {
                let Some(count) = args.first() else {
                    return Ok(self.graph.konst(mask(width.min(n)), n));
                };
                let count = self.lower(*count, width)?;
                let all = self.graph.konst(mask(width), width);
                let shifted = self.graph.shl(all, count);
                let ones = self.graph.not(shifted);
                Ok(self.masked(ones, n))
            }
            Op::Zeros => Ok(self.graph.konst(0, n)),
            other => Err(no_circuit(other)),
        }
    }

    fn divide(&mut self, width: u32, args: &[usize], signed: bool) -> Result<NodeId, String> {
        if width > 64 {
            return Err("a divider wider than 64 bits".to_string());
        }
        let a = self.lower(args[0], width)?;
        let b = self.lower(args[1], width)?;
        let signed = self.graph.konst(signed as u128, 1);
        Ok(self.graph.divrem(a, b, signed))
    }
}

/// Why an operator has no circuit, in words a census can group by.
fn no_circuit(op: Op) -> String {
    if ir::is_float_op(op) || format!("{op:?}").starts_with('F') {
        "floating point, which has no circuit yet".to_string()
    } else {
        format!("operator `{}`, which has no circuit yet", format!("{op:?}").to_lowercase())
    }
}

fn lower_expr_at(
    graph: &mut HwGraph,
    functions: &HashMap<String, Function>,
    sem: &Sem,
    env: &HashMap<String, NodeId>,
    n: u32,
    depth: u32,
) -> Result<NodeId, String> {
    let mut dag = SemDag::default();
    let root = dag.intern(sem);
    let mut scope = Scope {
        graph,
        functions,
        env,
        dag,
        demand: HashMap::new(),
        memo: HashMap::new(),
        recording: true,
        depth,
    };
    scope.lower(root, n)?;
    scope.recording = false;
    scope.memo.clear();
    scope.lower(root, n)
}

/// Lower `sem` to an `n`-bit node over `env`, which maps each symbol the
/// expression may read to the node that carries it.
pub fn lower_expr(
    graph: &mut HwGraph,
    functions: &HashMap<String, Function>,
    sem: &Sem,
    env: &HashMap<String, NodeId>,
    n: u32,
) -> Result<NodeId, String> {
    lower_expr_at(graph, functions, sem, env, n, 0)
}

/// One instruction's circuit: its inputs, and the node that carries its
/// result -- or the reason there is none.
pub struct HwDatapath {
    pub mnemonic: String,
    pub inputs: Vec<(String, u32)>,
    pub output_width: u32,
    /// ⚠️ A reason, not an absence. "No circuit was written for this
    /// operator" is a different fact from "the circuit is wrong", and a
    /// consumer that could not tell them apart would report a generator that
    /// builds less every release as one that still passes.
    pub root: Result<NodeId, String>,
    /// The functional unit the description assigns this instruction to, if it
    /// says.
    pub unit: String,
    /// The cycles the description says this instruction takes, which is what
    /// the cycle simulator charges for it.
    pub latency: u32,
}

pub struct HwDesign {
    pub graph: HwGraph,
    pub datapaths: Vec<HwDatapath>,
    pub behaviors: Vec<HwBehavior>,
    /// The cycle a core declares, in gate delays, when the design is one
    /// core's view of the description. `None` leaves the planner its rule.
    pub cycle: Option<f64>,
}

/// The name of the input that carries what a load read. Not an identifier a
/// description can write.
pub const LOAD_INPUT: &str = "%load";

/// What one effect writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectKind {
    /// A register operand.
    Set { dest: String },
    /// The program counter.
    SetPc,
    /// A named piece of architectural state -- a flag word, a mode register.
    SetState { name: String },
    /// Memory, `width` bits at the effect's address.
    Store,
}

pub struct HwEffect {
    pub kind: EffectKind,
    pub width: u32,
    pub value: NodeId,
    /// One bit: the effect happens. Absent when it always does.
    pub guard: Option<NodeId>,
    /// A store's address.
    pub addr: Option<NodeId>,
}

/// The one load an instruction makes: where from, how much, and whether what
/// comes back is sign-extended. What comes back is the input [`LOAD_INPUT`].
pub struct HwLoad {
    pub addr: NodeId,
    pub width: u32,
    pub signed: bool,
}

/// An instruction described by its EFFECTS -- a branch, a jump, a load, a
/// store -- as circuits: what each effect writes, when, and where.
///
/// A pure value has one result and is a [`HwDatapath`]. These have several,
/// read the program counter, and touch memory, and none of that is a
/// functional unit's business: memory is not built here. A load is an address
/// out and a value in; a store is an address and a value out. What sits on the
/// other side is the core's.
pub struct HwBehavior {
    pub mnemonic: String,
    /// The operands it reads, then `pc` if it reads the program counter, then
    /// each piece of architectural state it reads.
    pub inputs: Vec<(String, u32)>,
    /// Which of `inputs` are architectural state.
    pub state_inputs: Vec<String>,
    pub load: Option<HwLoad>,
    pub effects: Result<Vec<HwEffect>, String>,
    /// The functional unit the description assigns it to, if it says, and
    /// the cycles it declares: what a unit planner over effects groups by.
    pub unit: String,
    pub latency: u32,
}

/// Replace the load in `expr`, if there is one, by the input that carries its
/// result, and say what it loads. Two loads in one expression are declined: an
/// instruction that makes two accesses needs two memory ports or two cycles,
/// which is a decision about a core.
fn take_load(expr: &SemanticExpr, width: u32, found: &mut Vec<(SemanticExpr, u32, bool)>)
             -> SemanticExpr {
    if let Some((addr, access, signed)) = crate::effects::plain_load(expr) {
        found.push((addr.clone(), access, signed));
        let load = SemanticExpr::Atom(LOAD_INPUT.to_string());
        if !signed || access >= width {
            return load;
        }
        // `_mask(_signed(raw, access), width)`, as the golden model reads it.
        return SemanticExpr::List(vec![
            SemanticExpr::Atom("sext".to_string()),
            SemanticExpr::Atom(format!("i{width}")),
            SemanticExpr::Atom(access.to_string()),
            load,
        ]);
    }
    match expr {
        SemanticExpr::Atom(_) => expr.clone(),
        SemanticExpr::List(items) => {
            SemanticExpr::List(items.iter().map(|item| take_load(item, width, found)).collect())
        }
    }
}

/// Replace each use of an operator the typed IR does not carry by a call of
/// its REFERENCE BODY, where the description states one.
///
/// Some operators are implemented natively by every software backend and are
/// not in the IR at all -- AArch64's shifted register operand is one. A
/// netlist cannot be lowered from a name. A description says what such an
/// operator means, in its own operators, as `(deffun <operator>_ref_i<W> ...)`,
/// and a use at width `W` becomes the call the frontend would have written for
/// that function -- which the lowering then inlines like any other.
///
/// Nothing here knows any operator's name. `tools/hw_reference_check.py` is
/// what says a body means what its operator does.
fn with_references(expr: &SemanticExpr, functions: &HashMap<String, Function>) -> SemanticExpr {
    let SemanticExpr::List(items) = expr else { return expr.clone() };
    let rewritten: Vec<SemanticExpr> =
        items.iter().map(|item| with_references(item, functions)).collect();
    let Some(SemanticExpr::Atom(head)) = rewritten.first() else {
        return SemanticExpr::List(rewritten);
    };
    if ir::is_operator(head) || matches!(head.as_str(), "call" | "let" | "load" | "atomic_load") {
        return SemanticExpr::List(rewritten);
    }
    let Some(SemanticExpr::Atom(type_atom)) = rewritten.get(1) else {
        return SemanticExpr::List(rewritten);
    };
    let Some(width) = ir::type_atom_bits(type_atom) else {
        return SemanticExpr::List(rewritten);
    };
    let Some(function) = functions.get(&format!("{head}_ref_i{width}")) else {
        return SemanticExpr::List(rewritten);
    };
    let args = &rewritten[2..];
    if args.len() != function.params.len() {
        return SemanticExpr::List(rewritten);
    }
    let mut call = vec![
        SemanticExpr::Atom("call".to_string()),
        SemanticExpr::Atom(function.name.clone()),
        SemanticExpr::Atom(format!("i{}", function.result_width)),
    ];
    for ((_, param_width), arg) in function.params.iter().zip(args) {
        call.push(SemanticExpr::List(vec![
            SemanticExpr::Atom(format!("i{param_width}")),
            arg.clone(),
        ]));
    }
    SemanticExpr::List(call)
}

fn lower_behavior(
    graph: &mut HwGraph,
    functions: &HashMap<String, Function>,
    instruction: &crate::ast::Instruction,
    behavior: &crate::effects::Behavior,
    states: &[(String, u32)],
) -> HwBehavior {
    use crate::effects::{expr_atoms, Loc};
    let mut inputs: Vec<(String, u32)> = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| (operand.name.clone(), operand.width))
        .collect();
    // The program counter is an input like any other, as wide as the widest
    // expression that reads it.
    let mut pc_width = 0;
    for effect in &behavior.effects {
        let mut exprs = vec![&effect.value];
        exprs.extend(effect.guard.as_ref());
        if let Loc::Mem { addr, .. } = &effect.loc {
            exprs.push(addr);
        }
        for expr in exprs {
            if expr_atoms(&expr.expr).iter().any(|atom| atom == "pc") {
                pc_width = pc_width.max(expr.load_address_width.unwrap_or(0)).max(expr.width);
            }
        }
    }
    if pc_width > 0 {
        inputs.push(("pc".to_string(), pc_width));
    }
    // Architectural state an expression names is an input too: a flag word a
    // conditional reads comes in exactly as a register does.
    let mut state_inputs = Vec::new();
    for effect in &behavior.effects {
        let mut exprs = vec![&effect.value];
        exprs.extend(effect.guard.as_ref());
        if let Loc::Mem { addr, .. } = &effect.loc {
            exprs.push(addr);
        }
        for expr in exprs {
            for atom in expr_atoms(&expr.expr) {
                let Some((name, width)) = states.iter().find(|(name, _)| *name == atom) else {
                    continue;
                };
                if !inputs.iter().any(|(known, _)| known == name) {
                    inputs.push((name.clone(), *width));
                    state_inputs.push(name.clone());
                }
            }
        }
    }
    let mut env = HashMap::new();
    let mut load: Option<HwLoad> = None;
    let effects = (|| {
        for (name, width) in &inputs {
            if *width == 0 || *width > MAX_WIDTH {
                return Err(format!("an operand wider than {MAX_WIDTH} bits"));
            }
            env.insert(name.clone(), graph.input(name, *width));
        }
        let mut lowered = Vec::new();
        let mut loads: Vec<(SemanticExpr, u32, bool)> = Vec::new();
        let mut load_address: Option<NodeId> = None;
        // Lower one expression at `width`, taking out its load.
        let mut value_of = |graph: &mut HwGraph,
                            env: &mut HashMap<String, NodeId>,
                            expr: &crate::effects::EffectExpr,
                            width: u32,
                            loads: &mut Vec<(SemanticExpr, u32, bool)>,
                            load_address: &mut Option<NodeId>|
         -> Result<NodeId, String> {
            if width == 0 || width > MAX_WIDTH {
                return Err("an effect with no width, or one wider than the graph holds".to_string());
            }
            let before = loads.len();
            let taken = take_load(&with_references(&expr.expr, functions), width, loads);
            if loads.len() > before {
                if loads.len() > 1 {
                    return Err("more than one load".to_string());
                }
                // The address is lowered HERE, against the registers as the
                // effects before this one have left them: a pre-indexed load
                // reads from the base it has just updated.
                let address_width = expr.load_address_width.unwrap_or(pc_width.max(32));
                let address = ir::lower(&with_references(&loads[0].0, functions), address_width)
                    .map_err(|error| error.to_string())?;
                *load_address =
                    Some(lower_expr(graph, functions, &address, env, address_width)?);
                env.insert(LOAD_INPUT.to_string(), graph.input(LOAD_INPUT, loads[0].1));
            }
            let sem = ir::lower(&taken, width).map_err(|error| error.to_string())?;
            lower_expr(graph, functions, &sem, env, width)
        };
        for effect in &behavior.effects {
            let (kind, width, addr) = match &effect.loc {
                Loc::Reg(dest) => (EffectKind::Set { dest: dest.clone() }, effect.value.width, None),
                Loc::Pc => (EffectKind::SetPc, effect.value.width, None),
                Loc::Mem { addr, width, atomic, .. } => {
                    if *atomic {
                        return Err("an atomic store".to_string());
                    }
                    let address = value_of(
                        graph,
                        &mut env,
                        addr,
                        addr.width.max(1),
                        &mut loads,
                        &mut load_address,
                    )?;
                    (EffectKind::Store, *width, Some(address))
                }
                Loc::State { name, width } => {
                    (EffectKind::SetState { name: name.clone() }, *width, None)
                }
                Loc::Trap => return Err("a trap, which has no circuit yet".to_string()),
                _ => return Err("an effect that is not a register, pc or memory write".to_string()),
            };
            let value =
                value_of(graph, &mut env, &effect.value, width, &mut loads, &mut load_address)?;
            let guard = match &effect.guard {
                None => None,
                Some(guard) => {
                    let width = if guard.width == 0 { 32 } else { guard.width };
                    let condition =
                        value_of(graph, &mut env, guard, width, &mut loads, &mut load_address)?;
                    let zero = graph.konst(0, width);
                    let is_zero = graph.eq(condition, zero);
                    Some(graph.not(is_zero))
                }
            };
            // ⚠️ Effects happen IN ORDER. What this one writes is what the
            // next one reads: `rn = rn + imm; Mem[rn] = rt` stores at the
            // updated base. The executors get that from a register file they
            // have already written; here the name is rebound to the node that
            // carries the new value. The program counter is not threaded: a
            // jump-and-link sets it and then links the OLD one.
            let rebound = match &kind {
                EffectKind::Set { dest } => Some(dest),
                EffectKind::SetState { name } => Some(name),
                _ => None,
            };
            if let Some(name) = rebound {
                let held = match (guard, env.get(name).copied()) {
                    (Some(guard), Some(prior)) => {
                        let written = graph.resize(value, graph.width(prior));
                        graph.mux(guard, written, prior)
                    }
                    _ => value,
                };
                env.insert(name.clone(), held);
            }
            lowered.push(HwEffect { kind, width, value, guard, addr });
        }
        if let (Some(addr), Some((_, width, signed))) = (load_address, loads.first()) {
            load = Some(HwLoad { addr, width: *width, signed: *signed });
        }
        Ok(lowered)
    })();
    HwBehavior {
        mnemonic: instruction.mnemonic.clone(),
        inputs,
        state_inputs,
        load,
        effects,
        unit: instruction.unit.trim().to_string(),
        latency: instruction.latency_cycles.max(1),
    }
}

/// Each instruction's netlist under the calibrated cost model, by mnemonic:
/// `(area in NAND2 equivalents, depth in gate delays)`, for values and for
/// effects -- an effect's being its address, condition and value. An
/// instruction with no netlist is absent.
pub fn modelled_costs(document: &Document) -> HashMap<String, (f64, f64)> {
    let design = lower_document(document);
    let mut costs = HashMap::new();
    for datapath in &design.datapaths {
        if let Ok(root) = &datapath.root {
            costs.insert(datapath.mnemonic.clone(), design.graph.cone_cost(&[*root]));
        }
    }
    for behavior in &design.behaviors {
        let Ok(effects) = &behavior.effects else { continue };
        let mut roots: Vec<NodeId> = effects
            .iter()
            .flat_map(|effect| [Some(effect.value), effect.guard, effect.addr])
            .flatten()
            .collect();
        roots.extend(behavior.load.as_ref().map(|load| load.addr));
        costs.entry(behavior.mnemonic.clone()).or_insert_with(|| design.graph.cone_cost(&roots));
    }
    costs
}

/// Lower every instruction that states `formal_semantics`, into one graph --
/// so two instructions that compute the same thing are already one node.
pub fn lower_document(document: &Document) -> HwDesign {
    let functions: HashMap<String, Function> = document
        .functions
        .iter()
        .map(|function| (function.name.clone(), function.clone()))
        .collect();
    let mut graph = HwGraph::default();
    let mut datapaths = Vec::new();
    for instruction in &document.instructions {
        if instruction.formal_semantics.trim().is_empty() {
            continue;
        }
        let inputs: Vec<(String, u32)> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|operand| (operand.name.clone(), operand.width))
            .collect();
        // The same default the golden model's registry uses, so the two
        // describe one function.
        let output_width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(32);
        let root = (|| {
            if output_width == 0 || output_width > MAX_WIDTH {
                return Err(format!("a result wider than {MAX_WIDTH} bits"));
            }
            let mut env = HashMap::new();
            for (name, width) in &inputs {
                if *width == 0 || *width > MAX_WIDTH {
                    return Err(format!("an operand wider than {MAX_WIDTH} bits"));
                }
                env.insert(name.clone(), graph.input(name, *width));
            }
            let expr = parse_formal_semantics(&instruction.formal_semantics)
                .map_err(|error| error.to_string())?;
            let expr = with_references(&expr, &functions);
            let sem = ir::lower(&expr, output_width).map_err(|error| {
                // The IR names the operator it does not know; the census
                // wants the operator and not the sentence around it.
                let text = error.to_string();
                match text.split('`').nth(1) {
                    Some(name) if text.contains("unsupported formal_semantics operator") => {
                        format!("operator `{name}`, which the typed IR does not carry")
                    }
                    _ => text,
                }
            })?;
            lower_expr(&mut graph, &functions, &sem, &env, output_width)
        })();
        datapaths.push(HwDatapath {
            mnemonic: instruction.mnemonic.clone(),
            inputs,
            output_width,
            root,
            unit: instruction.unit.clone(),
            latency: instruction.latency_cycles.max(1),
        });
    }
    // Everything stated as effects and not as one value.
    let mut behaviors = Vec::new();
    let states = crate::effects::isa_scalar_state_slots(&document.isas);
    for instruction in &document.instructions {
        if !instruction.formal_semantics.trim().is_empty() {
            continue;
        }
        if let Some(behavior) = &instruction.behavior {
            if !behavior.effects.is_empty() {
                behaviors.push(lower_behavior(
                    &mut graph,
                    &functions,
                    instruction,
                    behavior,
                    &states,
                ));
            }
        }
    }
    HwDesign { graph, datapaths, behaviors, cycle: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(source: &str, operands: &[(&str, u32)], width: u32) -> (HwGraph, NodeId) {
        let mut graph = HwGraph::default();
        let mut env = HashMap::new();
        for (name, operand_width) in operands {
            env.insert(name.to_string(), graph.input(name, *operand_width));
        }
        let sem = ir::lower(&parse_formal_semantics(source).unwrap(), width).unwrap();
        let root = lower_expr(&mut graph, &HashMap::new(), &sem, &env, width).unwrap();
        (graph, root)
    }

    fn run(source: &str, operands: &[(&str, u32)], width: u32, values: &[u128]) -> u128 {
        let (graph, root) = build(source, operands, width);
        let inputs = operands
            .iter()
            .zip(values)
            .map(|((name, _), value)| (name.to_string(), *value))
            .collect();
        graph.eval(root, &inputs)
    }

    fn count(graph: &HwGraph, root: NodeId, op: HwOp) -> Vec<u32> {
        graph
            .cone(&[root])
            .into_iter()
            .filter(|id| graph.node(*id).op == op)
            .map(|id| graph.width(id))
            .collect()
    }

    const RR: &[(&str, u32)] = &[("rs1", 64), ("rs2", 64)];

    #[test]
    fn a_narrow_add_under_a_sign_extension_is_a_narrow_adder() {
        // ADDW. The adder is demanded at 32 bits because nothing above the
        // sign extension's source can reach the result.
        let (graph, root) = build("(sext i64 32 (add i32 rs1 rs2))", RR, 64);
        assert_eq!(count(&graph, root, HwOp::AddSub), vec![33]);
        let inputs = [("rs1".to_string(), 0x7fff_ffff), ("rs2".to_string(), 1)].into();
        assert_eq!(graph.eval(root, &inputs), 0xffff_ffff_8000_0000);
    }

    #[test]
    fn an_inner_type_atom_does_not_mask_a_ring_operator() {
        // The golden model does not mask `add`: an `i32` add read at 64 bits
        // is the 64-bit sum. A lowering that built a 32-bit adder here and
        // zero-extended it would be a different function.
        let value = run("(add i64 (add i32 rs1 rs2) 0)", RR, 64, &[0xffff_ffff, 1]);
        assert_eq!(value, 0x1_0000_0000);
    }

    #[test]
    fn a_chain_of_constant_steps_is_one_adder_deep() {
        // Four lanes of `x += 8`: each lane's value is `x` plus a constant, not the last
        // lane's value plus 8, and the constants wrap at the width.
        let (graph, root) = build("(add i64 (add i64 (add i64 (add i64 rs1 8) 8) 8) 8)", RR, 64);
        assert_eq!(count(&graph, root, HwOp::AddSub), vec![65]);
        assert_eq!(run("(add i64 (add i64 (add i64 (add i64 rs1 8) 8) 8) 8)", RR, 64, &[5, 0]), 37);
        let wrapped = "(add i64 (add i64 rs1 0xffffffffffffffff) 2)";
        assert_eq!(run(wrapped, RR, 64, &[u64::MAX as u128, 0]), 0);
        assert_eq!(count(&build(wrapped, RR, 64).0, build(wrapped, RR, 64).1, HwOp::AddSub), vec![65]);
    }

    #[test]
    fn subtract_and_both_comparisons_are_one_subtractor() {
        let mut graph = HwGraph::default();
        let (a, b) = (graph.input("rs1", 64), graph.input("rs2", 64));
        let roots = [graph.sub(a, b), graph.ult(a, b), graph.slt(a, b)];
        let adders: Vec<NodeId> = graph
            .cone(&roots)
            .into_iter()
            .filter(|id| graph.node(*id).op == HwOp::AddSub)
            .collect();
        assert_eq!(adders.len(), 1);
    }

    #[test]
    fn comparisons_agree_with_the_integers() {
        let cases: [(u128, u128); 6] = [
            (0, 0),
            (1, 2),
            (2, 1),
            (u64::MAX as u128, 0),
            (1 << 63, (1 << 63) - 1),
            ((1 << 63) - 1, 1 << 63),
        ];
        for (a, b) in cases {
            let (sa, sb) = (a as u64 as i64, b as u64 as i64);
            assert_eq!(run("(icmp_ult i64 rs1 rs2)", RR, 64, &[a, b]), (a < b) as u128);
            assert_eq!(run("(icmp_uge i64 rs1 rs2)", RR, 64, &[a, b]), (a >= b) as u128);
            assert_eq!(run("(icmp_slt i64 rs1 rs2)", RR, 64, &[a, b]), (sa < sb) as u128);
            assert_eq!(run("(icmp_sge i64 rs1 rs2)", RR, 64, &[a, b]), (sa >= sb) as u128);
            assert_eq!(run("(min i64 rs1 rs2)", RR, 64, &[a, b]), sa.min(sb) as u64 as u128);
            assert_eq!(run("(maxu i64 rs1 rs2)", RR, 64, &[a, b]), a.max(b));
        }
    }

    #[test]
    fn a_masked_shift_amount_is_a_narrow_shifter_and_no_gates() {
        let (graph, root) = build("(sll i64 rs1 (and i64 rs2 0x3f))", RR, 64);
        let shifters: Vec<NodeId> = graph
            .cone(&[root])
            .into_iter()
            .filter(|id| graph.node(*id).op == HwOp::Shr)
            .collect();
        assert_eq!(shifters.len(), 1);
        assert_eq!(graph.width(graph.node(shifters[0]).args[1]), 6);
        assert!(count(&graph, root, HwOp::And).is_empty());
        let inputs = [("rs1".to_string(), 3), ("rs2".to_string(), 0x41)].into();
        assert_eq!(graph.eval(root, &inputs), 6);
    }

    #[test]
    fn shifts_saturate_as_the_golden_model_does() {
        let top = 1u128 << 63;
        assert_eq!(run("(shl i64 rs1 rs2)", RR, 64, &[1, 64]), 0);
        assert_eq!(run("(lshr i64 rs1 rs2)", RR, 64, &[top, 63]), 1);
        assert_eq!(run("(lshr i64 rs1 rs2)", RR, 64, &[top, 64]), 0);
        assert_eq!(run("(ashr i64 rs1 rs2)", RR, 64, &[top, 200]), u64::MAX as u128);
        assert_eq!(run("(ashr i64 rs1 rs2)", RR, 64, &[top, 4]), 0xf800_0000_0000_0000);
        // A 32-bit shift read at 64 bits: in range it is the unmasked shift,
        // out of range it is zero, and the range is the TYPE's.
        assert_eq!(run("(add i64 (shl i32 rs1 rs2) 0)", RR, 64, &[1, 40]), 0);
        assert_eq!(run("(add i64 (shl i32 rs1 rs2) 0)", RR, 64, &[3, 31]), 3 << 31);
    }

    #[test]
    fn a_shift_by_a_constant_is_wires() {
        let (graph, root) = build("(or i64 (shl i64 rs1 12) (lshr i64 rs2 52))", RR, 64);
        assert!(count(&graph, root, HwOp::Shr).is_empty());
        let inputs = [("rs1".to_string(), 1), ("rs2".to_string(), 1 << 52)].into();
        assert_eq!(graph.eval(root, &inputs), 0x1001);
    }

    #[test]
    fn division_follows_the_axis_rule() {
        let neg = |value: i64| value as u64 as u128;
        assert_eq!(run("(udiv i64 rs1 rs2)", RR, 64, &[7, 0]), 0);
        assert_eq!(run("(urem i64 rs1 rs2)", RR, 64, &[7, 0]), 0);
        assert_eq!(run("(sdiv i64 rs1 rs2)", RR, 64, &[neg(-7), 2]), neg(-3));
        assert_eq!(run("(srem i64 rs1 rs2)", RR, 64, &[neg(-7), 2]), neg(-1));
        assert_eq!(run("(srem i64 rs1 rs2)", RR, 64, &[7, neg(-2)]), 1);
        assert_eq!(run("(sdiv i64 rs1 rs2)", RR, 64, &[neg(i64::MIN), neg(-1)]), neg(i64::MIN));
        // A signed quotient read above its type is sign-extended, and the one
        // that overflows is not.
        let wide = "(add i64 (sdiv i32 rs1 rs2) 0)";
        assert_eq!(run(wide, RR, 64, &[neg(-8), 2]), neg(-4));
        assert_eq!(run(wide, RR, 64, &[0x8000_0000, 0xffff_ffff]), 0x8000_0000);
    }

    #[test]
    fn a_remainder_written_as_a_multiply_and_subtract_is_the_dividers() {
        // RISC-V's `REM`. The rewrite drops the multiplier and the subtractor,
        // and it is checked on every pair of bytes because z3 will not finish
        // the same identity at 32 bits (`hw_prove.py` says so by name).
        const AB: &[(&str, u32)] = &[("a", 8), ("b", 8)];
        for (source, signed) in [
            ("(sub i8 a (mul i8 (sdiv i8 a b) b))", true),
            ("(sub i8 a (mul i8 (udiv i8 a b) b))", false),
        ] {
            let (graph, root) = build(source, AB, 8);
            assert!(count(&graph, root, HwOp::Mul).is_empty(), "{source} kept its multiplier");
            assert!(count(&graph, root, HwOp::AddSub).is_empty(), "{source} kept its subtractor");
            for a in 0..=255u128 {
                for b in 0..=255u128 {
                    let quotient = if b == 0 {
                        0
                    } else if signed {
                        (a as u8 as i8 as i32).wrapping_div(b as u8 as i8 as i32)
                    } else {
                        (a / b) as i32
                    };
                    let want = (a as i32 - quotient * if signed { b as u8 as i8 as i32 } else { b as i32 })
                        as u128
                        & 0xff;
                    let inputs = [("a".to_string(), a), ("b".to_string(), b)].into();
                    assert_eq!(graph.eval(root, &inputs), want, "{source} at {a}, {b}");
                }
            }
        }
    }

    #[test]
    fn the_high_half_of_a_product() {
        let neg = |value: i64| value as u64 as u128;
        assert_eq!(run("(mulhu i64 rs1 rs2)", RR, 64, &[u64::MAX as u128, 2]), 1);
        assert_eq!(run("(mulh i64 rs1 rs2)", RR, 64, &[neg(-1), 2]), neg(-1));
        assert_eq!(run("(mulhsu i64 rs1 rs2)", RR, 64, &[neg(-1), u64::MAX as u128]), neg(-1));
        assert_eq!(run("(mulhsu i64 rs1 rs2)", RR, 64, &[2, u64::MAX as u128]), 1);
    }

    #[test]
    fn counts_rotates_and_masks() {
        let one = &[("rs1", 64)][..];
        assert_eq!(run("(clz i64 rs1)", one, 64, &[0]), 64);
        assert_eq!(run("(clz i64 rs1)", one, 64, &[1]), 63);
        assert_eq!(run("(ctz i64 rs1)", one, 64, &[0]), 64);
        assert_eq!(run("(ctz i64 rs1)", one, 64, &[8]), 3);
        assert_eq!(run("(cpop i64 rs1)", one, 64, &[0xf0f0]), 8);
        assert_eq!(run("(ror i32 rs1 rs2)", RR, 32, &[1, 1]), 0x8000_0000);
        assert_eq!(run("(rol i32 rs1 rs2)", RR, 32, &[0x8000_0000, 33]), 1);
        assert_eq!(run("(ones i64 rs1)", one, 64, &[5]), 31);
        assert_eq!(run("(ones i64 rs1)", one, 64, &[99]), u64::MAX as u128);
    }

    #[test]
    fn a_condition_of_two_comparisons_is_two_bits_and_one_gate() {
        let (graph, root) = build(
            "(select i64 (and i64 (icmp_eq i64 rs1 5) (icmp_eq i64 rs2 7)) rs1 rs2)",
            RR,
            64,
        );
        assert_eq!(count(&graph, root, HwOp::And), vec![1]);
        let inputs = [("rs1".to_string(), 5), ("rs2".to_string(), 7)].into();
        assert_eq!(graph.eval(root, &inputs), 5);
        let inputs = [("rs1".to_string(), 5), ("rs2".to_string(), 8)].into();
        assert_eq!(graph.eval(root, &inputs), 8);
    }

    #[test]
    fn a_bound_value_wanted_at_two_widths_is_built_once() {
        // `t` is demanded at 32 bits by the extension and at 64 by the add.
        // It is lowered once, at 64, and the narrow use slices it.
        let (graph, root) = build(
            "(let ((t (add i64 rs1 rs2))) (xor i64 t (sext i64 32 t)))",
            RR,
            64,
        );
        assert_eq!(count(&graph, root, HwOp::AddSub), vec![65]);
    }

    #[test]
    fn what_has_no_circuit_says_so() {
        let mut graph = HwGraph::default();
        let env = [("rs1".to_string(), graph.input("rs1", 64))].into();
        let lower = |graph: &mut HwGraph, source: &str| {
            let sem = ir::lower(&parse_formal_semantics(source).unwrap(), 64).unwrap();
            lower_expr(graph, &HashMap::new(), &sem, &env, 64)
        };
        assert!(lower(&mut graph, "(fadd f64 rs1 rs1)").unwrap_err().contains("floating point"));
        assert!(lower(&mut graph, "(add i64 rs1 pc)").unwrap_err().contains("not an operand"));
        assert!(lower(&mut graph, "(ror i24 rs1 rs1)").unwrap_err().contains("power of two"));
    }
}
