//! Functional units: which instructions share a datapath, and the datapath
//! they share.
//!
//! One instruction's circuit ([`crate::hw`]) is not a design. Thirty-eight
//! instructions are thirty-eight adders, and a core has one. The instructions
//! of a unit never run in the same cycle, so two of them can use one operator
//! -- at the price of a multiplexer on each input they do not already agree
//! about. Choosing which operators to share is *datapath merging*, and this
//! module does it in two steps:
//!
//! * [`plan_units`] decides **which instructions belong together**: the
//!   description's own `(unit ...)` tags where every instruction has one, and
//!   otherwise by rule -- what fits in a cycle is the ALU, what does not is
//!   named for its largest operator -- refined by cost: two slow units are
//!   joined when merging them is measurably smaller than keeping them apart,
//!   which is how a multiplier and a divider that both need a multiplier
//!   become one `muldiv`.
//! * [`merge_unit`] decides **which operators become one**: each heavy node is
//!   bound to an operator instance no instruction that needs it is already
//!   using, preferring the instance whose inputs it already matches, and only
//!   when the muxes that costs are smaller than the operator saved.
//!
//! ⚠️ Neither choice can make the unit WRONG. A merged unit is rebuilt from the
//! same nodes over muxed inputs, every instruction's result is recovered by
//! construction, and `tools/hw_units_check.py` holds each one to the golden
//! model anyway. The choices only move area and depth -- which is what makes
//! them safe to hand to a search, a learned cost model or a language model
//! later: a proposer can be wrong about what is small, never about what is
//! computed.

use std::collections::{BTreeSet, HashMap, HashSet};

use crate::hw::{
    adder_cost, bit_length, ceil_log2, divider_cost, leading_zeros_cost, mask, multiplier_cost,
    population_cost, rotator_cost, shifter_cost, wide_multiplier_cost, EffectKind, HwDesign,
    HwGraph, HwOp, NodeId, GE_MUX, LOAD_INPUT, SELECT_INPUT,
};

/// The operators worth sharing. Gates and wires are not: a mux costs more
/// than the gate it would save.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum UnitClass {
    AddSub,
    Mul,
    MulWide,
    DivRem,
    Shift,
    Rotate,
    Clz,
    Cpop,
}

impl UnitClass {
    pub const ALL: [UnitClass; 8] = [
        UnitClass::AddSub,
        UnitClass::Mul,
        UnitClass::MulWide,
        UnitClass::DivRem,
        UnitClass::Shift,
        UnitClass::Rotate,
        UnitClass::Clz,
        UnitClass::Cpop,
    ];

    /// The operators of this class, as `HwGraph::cone_area_by_operator`
    /// names them.
    fn operators(self) -> &'static [&'static str] {
        match self {
            UnitClass::AddSub => &["addsub"],
            UnitClass::Mul => &["mul"],
            UnitClass::MulWide => &["mulwide"],
            UnitClass::DivRem => &["divrem"],
            UnitClass::Shift => &["shr"],
            UnitClass::Rotate => &["ror"],
            UnitClass::Clz => &["clz"],
            UnitClass::Cpop => &["cpop"],
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            UnitClass::AddSub => "addsub",
            UnitClass::Mul => "mul",
            UnitClass::MulWide => "mulwide",
            UnitClass::DivRem => "divrem",
            UnitClass::Shift => "shift",
            UnitClass::Rotate => "rotate",
            UnitClass::Clz => "clz",
            UnitClass::Cpop => "cpop",
        }
    }

    pub fn of(op: HwOp) -> Option<UnitClass> {
        Some(match op {
            HwOp::AddSub => UnitClass::AddSub,
            HwOp::Mul => UnitClass::Mul,
            HwOp::MulWide => UnitClass::MulWide,
            HwOp::DivRem => UnitClass::DivRem,
            HwOp::Shr => UnitClass::Shift,
            HwOp::Ror => UnitClass::Rotate,
            HwOp::Clz => UnitClass::Clz,
            HwOp::Cpop => UnitClass::Cpop,
            _ => return None,
        })
    }

    fn op(self) -> HwOp {
        match self {
            UnitClass::AddSub => HwOp::AddSub,
            UnitClass::Mul => HwOp::Mul,
            UnitClass::MulWide => HwOp::MulWide,
            UnitClass::DivRem => HwOp::DivRem,
            UnitClass::Shift => HwOp::Shr,
            UnitClass::Rotate => HwOp::Ror,
            UnitClass::Clz => HwOp::Clz,
            UnitClass::Cpop => HwOp::Cpop,
        }
    }

    fn ports(self) -> usize {
        match self {
            UnitClass::AddSub | UnitClass::DivRem | UnitClass::Shift => 3,
            UnitClass::Mul | UnitClass::Rotate => 2,
            UnitClass::MulWide => 4,
            UnitClass::Clz | UnitClass::Cpop => 1,
        }
    }

    /// How wide input `port` is on an instance `n` bits wide.
    fn port_width(self, port: usize, n: u32, amount: u32) -> u32 {
        match (self, port) {
            (UnitClass::AddSub | UnitClass::DivRem | UnitClass::Shift, 2) => 1,
            (UnitClass::MulWide, 2 | 3) => 1,
            (UnitClass::Shift, 1) => amount,
            (UnitClass::Rotate, 1) => ceil_log2(n),
            _ => n,
        }
    }

    /// Which of a node's arguments feeds `port`, when its two data operands
    /// are taken in the other order.
    fn argument(self, port: usize, swapped: bool) -> usize {
        if !swapped {
            return port;
        }
        match port {
            0 => 1,
            1 => 0,
            2 if self == UnitClass::MulWide => 3,
            3 if self == UnitClass::MulWide => 2,
            other => other,
        }
    }

    /// What an instance this wide costs, for weighing a widening.
    fn area(self, n: u32, amount: u32) -> f64 {
        match self {
            UnitClass::AddSub => adder_cost(n).0,
            UnitClass::Mul => multiplier_cost(n, false).0,
            UnitClass::MulWide => wide_multiplier_cost(n, true).0,
            UnitClass::DivRem => divider_cost(n, true).0,
            UnitClass::Shift => shifter_cost(n, amount).0,
            UnitClass::Rotate => rotator_cost(n).0,
            UnitClass::Clz => leading_zeros_cost(n).0,
            UnitClass::Cpop => population_cost(n).0,
        }
    }
}

/// The width of the data a heavy node works on, which is not always the
/// width of what it returns.
fn data_width(graph: &HwGraph, id: NodeId) -> u32 {
    let node = graph.node(id);
    match node.op {
        HwOp::AddSub => node.width - 1,
        HwOp::MulWide | HwOp::DivRem => node.width / 2,
        HwOp::Clz | HwOp::Cpop => graph.width(node.args[0]),
        _ => node.width,
    }
}

#[derive(Clone)]
struct Instance {
    class: UnitClass,
    width: u32,
    amount_width: u32,
    /// The nodes this instance computes, and whether each takes its data
    /// operands swapped.
    bound: Vec<(NodeId, bool)>,
    /// The members (by select code) that use it. Two nodes of one member can
    /// never share an instance: both are live in the same cycle.
    members: BTreeSet<usize>,
    /// Per port, the arguments already wired to it.
    sources: Vec<BTreeSet<(NodeId, u32)>>,
    /// Instances whose inputs depend on this one's output.
    consumers: BTreeSet<usize>,
}

/// One operator instance of a merged unit, as a report.
pub struct InstanceReport {
    pub class: &'static str,
    pub width: u32,
    /// How many distinct nodes it computes.
    pub nodes: usize,
    /// The members that use it, by select code.
    pub members: Vec<usize>,
}

pub struct MergedUnit {
    pub name: String,
    /// Indices into [`HwDesign::datapaths`]; a member's position here is its
    /// select code.
    pub members: Vec<usize>,
    /// Zero for a unit of one instruction, which has no select input.
    pub select_width: u32,
    pub inputs: Vec<(String, u32)>,
    pub output_width: u32,
    pub root: NodeId,
    /// The cycles every member declares. A unit's members agree, because the
    /// plan never puts two latencies in one unit.
    pub latency: u32,
    pub instances: Vec<InstanceReport>,
    /// Every member's circuit built on its own, plus the result mux.
    pub area_separate: f64,
    /// Identical nodes built once -- what hash-consing alone gives.
    pub area_identical: f64,
    pub area_merged: f64,
    /// Where the merged area is, by kind of operator.
    pub area_by_operator: Vec<(String, f64)>,
    /// Classes that could have shared and were left apart for saving less
    /// than [`SHARING_MARGIN`].
    pub kept_apart: Vec<KeptApart>,
    pub depth_slowest_member: f64,
    pub depth_merged: f64,
}

struct Merger<'a> {
    graph: &'a mut HwGraph,
    select: Option<NodeId>,
    select_width: u32,
    /// For each node, the members whose result depends on it.
    users: HashMap<NodeId, Vec<usize>>,
    binding: HashMap<NodeId, (usize, bool)>,
    /// Adders whose carry nothing reads: only their low bits are used.
    low_only: HashSet<NodeId>,
    /// A constant zero bit: the sign flags of a plain multiply on a wide
    /// multiplier.
    zero: NodeId,
    policy: Sharing,
    /// Classes whose operators each stay an instance of their own.
    apart: Vec<UnitClass>,
    instances: Vec<Instance>,
    /// For an unbound node, the instances nearest above it.
    frontier: HashMap<NodeId, BTreeSet<usize>>,
    outputs: Vec<Option<NodeId>>,
    rebuilt: HashMap<NodeId, NodeId>,
}

impl Merger<'_> {
    /// Whether a node's data operands may be driven with ANY bits above its
    /// own width. A product's low bits and a sum's low bits depend only on the
    /// operands' low bits, so when nothing reads above them the wide operator
    /// can be fed the wide value the narrow operand was sliced from.
    ///
    /// ⚠️ This is what puts `ADDW` on `ADD`'s adder with no mux at all: both
    /// read `rs1` and `rs2`, and a rule that zero-extended the narrow operands
    /// would make them different sources and pay 128 mux bits to save 32 adder
    /// bits -- which the cost test rightly refuses, leaving two adders.
    fn relaxed(&self, id: NodeId) -> bool {
        match self.graph.node(id).op {
            HwOp::Mul => true,
            HwOp::AddSub => self.low_only.contains(&id),
            _ => false,
        }
    }

    /// A node's arguments as an instance of `class` takes them. They are the
    /// node's own, except that a plain multiply on a wide multiplier -- whose
    /// low word is the same product whatever the signs -- brings two clear
    /// sign flags.
    fn arguments(&self, id: NodeId, class: UnitClass) -> Vec<NodeId> {
        let node = self.graph.node(id);
        let mut args = node.args.clone();
        if node.op == HwOp::Mul && class == UnitClass::MulWide {
            args.extend([self.zero, self.zero]);
        }
        args
    }

    /// What identifies the wire a node drives into `port`.
    fn source_key(&self, id: NodeId, class: UnitClass, port: usize, swapped: bool, n: u32)
                  -> (NodeId, u32) {
        let arg = self.arguments(id, class)[class.argument(port, swapped)];
        if port < 2 && self.relaxed(id) {
            let node = self.graph.node(arg);
            if node.op == HwOp::Slice && node.value == 0 {
                return (node.args[0], 0);
            }
            return (arg, 0);
        }
        // A one-bit control input is the same wire at any data width.
        if class.port_width(port, 2, 2) == 1 && class != UnitClass::Rotate {
            return (arg, 0);
        }
        (arg, n)
    }

    /// `source` at `n` bits with whatever lies above it: the value it was
    /// sliced from where there is one, zeros otherwise.
    fn widen(&mut self, source: NodeId, n: u32) -> NodeId {
        let node = self.graph.node(source).clone();
        if node.op == HwOp::Slice && node.value == 0 {
            let whole = node.args[0];
            return self.graph.resize(whole, n);
        }
        self.graph.zext(source, n)
    }

    fn frontier_of(&mut self, id: NodeId) -> BTreeSet<usize> {
        if let Some((instance, _)) = self.binding.get(&id) {
            return BTreeSet::from([*instance]);
        }
        if let Some(known) = self.frontier.get(&id) {
            return known.clone();
        }
        let args = self.graph.node(id).args.clone();
        let mut found = BTreeSet::new();
        for arg in args {
            found.extend(self.frontier_of(arg));
        }
        self.frontier.insert(id, found.clone());
        found
    }

    /// Whether `from`'s output can reach an input of any of `targets`.
    fn reaches(&self, from: usize, targets: &BTreeSet<usize>) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = vec![from];
        while let Some(instance) = stack.pop() {
            if targets.contains(&instance) {
                return true;
            }
            if seen.insert(instance) {
                stack.extend(self.instances[instance].consumers.iter().copied());
            }
        }
        false
    }

    /// Bind every heavy node to an instance, in topological order -- so a
    /// node's own inputs are already placed when it is.
    fn bind(&mut self, cone: &[NodeId]) {
        for &id in cone {
            let node = self.graph.node(id).clone();
            let Some(class) = UnitClass::of(node.op) else { continue };
            let n = data_width(self.graph, id);
            let amount = match class {
                UnitClass::Shift => self.graph.width(node.args[1]),
                _ => 0,
            };
            let members = self.users[&id].clone();
            let mut feeders = BTreeSet::new();
            for arg in &node.args {
                feeders.extend(self.frontier_of(*arg));
            }
            let commutes = match class {
                UnitClass::AddSub => self.graph.as_const(node.args[2]) == Some(0),
                UnitClass::Mul => true,
                UnitClass::MulWide => node.args[2] == node.args[3],
                _ => false,
            };
            // A multiply and a wide multiply can be one multiplier: the wide
            // one, whose low word is the plain product.
            let multiplies = |class: UnitClass| matches!(class, UnitClass::Mul | UnitClass::MulWide);
            let own_area = self.graph.node_cost(id).0;
            let mut best: Option<(f64, usize, bool)> = None;
            for (index, instance) in self.instances.iter().enumerate() {
                if !(instance.class == class || (multiplies(class) && multiplies(instance.class)))
                    || members.iter().any(|member| instance.members.contains(member))
                    || (class == UnitClass::Rotate && instance.width != n)
                {
                    continue;
                }
                // ⚠️ No combinational loop, even a false one. If this instance
                // already feeds one of the node's own feeders, binding here
                // closes a cycle through two muxes that no instruction ever
                // selects together -- and that a netlist tool rejects anyway.
                if self.reaches(index, &feeders) {
                    continue;
                }
                let (width, amount_width) =
                    (instance.width.max(n), instance.amount_width.max(amount));
                // The instance as it would be with this node on it: wider if
                // the node is, and a wide multiplier if either is.
                let joined = instance.class.max(class);
                let widening = joined.area(width, amount_width)
                    - instance.class.area(instance.width, instance.amount_width);
                for swapped in [false, true] {
                    if swapped && !commutes {
                        continue;
                    }
                    let mut muxes = 0.0;
                    for port in 0..joined.ports() {
                        let source = self.source_key(id, joined, port, swapped, n);
                        let known = instance.sources.get(port).is_some_and(|set| set.contains(&source));
                        // A port the instance does not have yet carries one
                        // value so far -- clear -- and costs a mux only if
                        // this node brings another.
                        let fresh = port >= instance.sources.len() && source.0 == self.zero;
                        if !known && !fresh {
                            muxes += GE_MUX * joined.port_width(port, width, amount_width) as f64;
                        }
                    }
                    let delta = muxes + widening - own_area;
                    if best.map_or(true, |(least, _, _)| delta < least) {
                        best = Some((delta, index, swapped));
                    }
                }
            }
            let (index, swapped) = match best {
                Some((delta, index, swapped))
                    if !self.apart.contains(&class)
                        && (delta < 0.0 || self.policy == Sharing::Always) =>
                {
                    (index, swapped)
                }
                _ => {
                    self.instances.push(Instance {
                        class,
                        width: n,
                        amount_width: amount,
                        bound: Vec::new(),
                        members: BTreeSet::new(),
                        sources: vec![BTreeSet::new(); class.ports()],
                        consumers: BTreeSet::new(),
                    });
                    (self.instances.len() - 1, false)
                }
            };
            let joined = self.instances[index].class.max(class);
            let keys: Vec<(NodeId, u32)> = (0..joined.ports())
                .map(|port| self.source_key(id, joined, port, swapped, n))
                .collect();
            let zero = self.zero;
            let instance = &mut self.instances[index];
            if instance.class != joined {
                // Promoted to a wide multiplier: what it already computes
                // takes the new sign inputs clear.
                instance.class = joined;
                instance.sources.resize(joined.ports(), BTreeSet::from([(zero, 0)]));
            }
            instance.width = instance.width.max(n);
            instance.amount_width = instance.amount_width.max(amount);
            instance.bound.push((id, swapped));
            instance.members.extend(members);
            for (port, source) in keys.into_iter().enumerate() {
                instance.sources[port].insert(source);
            }
            for feeder in feeders {
                self.instances[feeder].consumers.insert(index);
            }
            self.binding.insert(id, (index, swapped));
        }
    }

    /// One bit: the unit is running member `member`.
    fn running(&mut self, member: usize) -> NodeId {
        let select = self.select.expect("a unit of one member selects nothing");
        let code = self.graph.konst(member as u128, self.select_width);
        self.graph.eq(select, code)
    }

    /// One bit: the unit is running one of `members`. A balanced OR, because a
    /// unit of fifty instructions would otherwise put fifty gates in series in
    /// front of every mux it has.
    fn any_running(&mut self, members: &[usize]) -> NodeId {
        match members {
            [] => self.graph.konst(0, 1),
            [member] => self.running(*member),
            _ => {
                let (left, right) = members.split_at(members.len() / 2);
                let (left, right) = (self.any_running(left), self.any_running(right));
                self.graph.or(left, right)
            }
        }
    }

    /// One wire out of several, chosen by which member is running: a balanced
    /// tree of two-way muxes, each steered by "one of the members on my left
    /// is running". When no member that uses the wire is running, nothing
    /// reads it, so no source needs a decode of its own to be the default.
    ///
    /// The sources most members want sit on the right of every split, so the
    /// decode is built from the short lists.
    fn choose(&mut self, mut groups: Vec<(NodeId, Vec<usize>)>) -> NodeId {
        groups.sort_by_key(|(source, members)| (members.len(), *source));
        self.choose_sorted(&groups)
    }

    fn choose_sorted(&mut self, groups: &[(NodeId, Vec<usize>)]) -> NodeId {
        if let [(source, _)] = groups {
            return *source;
        }
        let (left, right) = groups.split_at(groups.len() / 2);
        let members: Vec<usize> = left.iter().flat_map(|(_, members)| members.iter().copied()).collect();
        let steer = self.any_running(&members);
        let (left, right) = (self.choose_sorted(left), self.choose_sorted(right));
        self.graph.mux(steer, left, right)
    }

    /// `value` with `bit` repeated above it, out to `n` bits.
    fn extend_with(&mut self, value: NodeId, bit: NodeId, n: u32) -> NodeId {
        let width = self.graph.width(value);
        if width == n {
            return value;
        }
        let upper = self.graph.sext(bit, n - width);
        self.graph.concat(upper, value)
    }

    /// `value` sign-extended to `n` bits when `signed` is set, zero-extended
    /// otherwise.
    fn extend_if(&mut self, value: NodeId, signed: NodeId, n: u32) -> NodeId {
        let width = self.graph.width(value);
        if width == n {
            return value;
        }
        let top = self.graph.slice(value, width - 1, 1);
        let bit = self.graph.and(signed, top);
        self.extend_with(value, bit, n)
    }

    /// What a node narrower than its instance drives into `port`. Every case
    /// is the extension under which the wide operator's low bits are the
    /// narrow operator's result.
    fn drive(&mut self, class: UnitClass, port: usize, args: &[NodeId], swapped: bool, n: u32,
             amount: u32, relaxed: bool) -> NodeId {
        let source = args[class.argument(port, swapped)];
        if relaxed && port < 2 {
            return self.widen(source, n);
        }
        match (class, port) {
            (UnitClass::AddSub, 0 | 1) | (UnitClass::Mul, _) | (UnitClass::Cpop, _) => {
                self.graph.zext(source, n)
            }
            (UnitClass::MulWide, 0 | 1) => {
                let signed = args[class.argument(port + 2, swapped)];
                self.extend_if(source, signed, n)
            }
            (UnitClass::DivRem, 0 | 1) => self.extend_if(source, args[2], n),
            // The bits a right shift brings in from above are its fill.
            (UnitClass::Shift, 0) => self.extend_with(source, args[2], n),
            (UnitClass::Shift, 1) => self.graph.zext(source, amount),
            // Counted from the top, so the value sits at the top and the bits
            // below it are ones: a zero value still counts only its own width.
            (UnitClass::Clz, _) => {
                let width = self.graph.width(source);
                if width == n {
                    source
                } else {
                    let ones = self.graph.konst(mask(n - width), n - width);
                    self.graph.concat(source, ones)
                }
            }
            _ => source,
        }
    }

    /// A bound node's own result, read back out of its instance.
    fn view(&mut self, id: NodeId, instance: usize, unit: NodeId) -> NodeId {
        let node = self.graph.node(id).clone();
        let (class, n) = (self.instances[instance].class, self.instances[instance].width);
        let own = data_width(self.graph, id);
        match class {
            UnitClass::AddSub if own == n => unit,
            // Nothing reads this adder's carry, and its operands were driven
            // with bits above their width, so there is no carry to recover.
            UnitClass::AddSub if self.low_only.contains(&id) => {
                let low = self.graph.slice(unit, 0, own);
                self.graph.zext(low, own + 1)
            }
            // Subtracting zero-extended operands leaves the BORROW in the bit
            // above the narrow result where adding leaves the carry, so the
            // narrow carry is that bit flipped when subtracting.
            UnitClass::AddSub => {
                let above = self.graph.slice(unit, own, 1);
                let sub = self.rebuild(node.args[2]);
                let carry = self.graph.xor(above, sub);
                let low = self.graph.slice(unit, 0, own);
                self.graph.concat(carry, low)
            }
            UnitClass::DivRem if own == n => unit,
            UnitClass::DivRem => {
                let remainder = self.graph.slice(unit, n, own);
                let quotient = self.graph.slice(unit, 0, own);
                self.graph.concat(remainder, quotient)
            }
            UnitClass::MulWide if node.op == HwOp::Mul => self.graph.slice(unit, 0, own),
            UnitClass::MulWide => self.graph.slice(unit, 0, 2 * own),
            UnitClass::Clz | UnitClass::Cpop => self.graph.slice(unit, 0, bit_length(own)),
            UnitClass::Mul | UnitClass::Shift | UnitClass::Rotate => {
                self.graph.slice(unit, 0, own)
            }
        }
    }

    fn build_instance(&mut self, index: usize) -> NodeId {
        if let Some(output) = self.outputs[index] {
            return output;
        }
        let instance = self.instances[index].clone();
        let (class, n, amount) = (instance.class, instance.width, instance.amount_width);
        let mut ports: Vec<Vec<(NodeId, Vec<usize>)>> = vec![Vec::new(); class.ports()];
        for (id, swapped) in &instance.bound {
            let members = self.users[id].clone();
            let args: Vec<NodeId> =
                self.arguments(*id, class).into_iter().map(|arg| self.rebuild(arg)).collect();
            let relaxed = self.relaxed(*id);
            for (port, groups) in ports.iter_mut().enumerate() {
                let source = self.drive(class, port, &args, *swapped, n, amount, relaxed);
                match groups.iter_mut().find(|(known, _)| *known == source) {
                    Some((_, users)) => users.extend(members.iter().copied()),
                    None => groups.push((source, members.clone())),
                }
            }
        }
        let inputs: Vec<NodeId> = ports.into_iter().map(|groups| self.choose(groups)).collect();
        let width = match class {
            UnitClass::AddSub => n + 1,
            UnitClass::MulWide | UnitClass::DivRem => 2 * n,
            UnitClass::Clz | UnitClass::Cpop => bit_length(n),
            _ => n,
        };
        let output = self.graph.make(class.op(), width, 0, &inputs);
        self.outputs[index] = Some(output);
        output
    }

    /// The node that carries `id`'s value in the merged unit. A node's cone is
    /// the same for every member that reaches it, so this depends on the node
    /// alone.
    fn rebuild(&mut self, id: NodeId) -> NodeId {
        if let Some(done) = self.rebuilt.get(&id) {
            return *done;
        }
        let node = self.graph.node(id).clone();
        let out = if let Some((instance, _)) = self.binding.get(&id).copied() {
            let unit = self.build_instance(instance);
            self.view(id, instance, unit)
        } else if node.args.is_empty() {
            id
        } else {
            let args: Vec<NodeId> = node.args.iter().map(|arg| self.rebuild(*arg)).collect();
            if args == node.args {
                id
            } else {
                self.graph.make(node.op, node.width, node.value, &args)
            }
        };
        self.rebuilt.insert(id, out);
        out
    }
}

/// When a node joins an instance it is allowed to join.
///
/// The seam a proposer drives. Whatever the policy, the unit computes the same
/// thing; the policy only decides what it costs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sharing {
    /// When the muxes cost less than the operator saved.
    WhenItPays,
    /// Whenever it is legal. The fewest operators, whatever the muxes cost --
    /// and the policy the tests use to put every narrow operator on a wide
    /// one, where the extension rules are.
    Always,
    /// Never: every operator an instance of its own, identical ones still
    /// one. What sharing is measured against, as a unit that can be built.
    Never,
}

/// Merge the given datapaths, each of which must have a circuit, into one
/// unit.
pub fn merge_unit(design: &mut HwDesign, name: &str, members: &[usize]) -> MergedUnit {
    merge_unit_with(design, name, members, Sharing::WhenItPays)
}

/// The least of what a class's sharing removes that it has to keep.
///
/// Sharing removes operators and adds what steers the one that is left:
/// muxes on its ports, a wider select, and whatever the unit loses because
/// two operators no longer read the same value. The cost model prices the
/// first well and the second badly, and always in sharing's favour. So a
/// share is taken when it saves at least half of the operator area it
/// removes -- when what it adds, as the model prices it, could be twice as
/// large and the share still not lose.
///
/// Measured through Yosys, class by class (`docs/hardware_design.md` §5.2):
/// the adder and shifter of RV32I's ALU keep 71% and 98% by the model and
/// both save area synthesised; zbb_like's rotator and comparator keep 36%
/// and 6% and both COST area synthesised.
pub const SHARING_MARGIN: f64 = 0.5;

/// A class the merger could have shared and left apart, and why.
#[derive(Debug, Clone)]
pub struct KeptApart {
    pub class: &'static str,
    /// The operator area sharing it would remove.
    pub removes: f64,
    /// What the cost model says the unit would save: that, less what steers
    /// the shared operator.
    pub saves: f64,
    /// `"area"`: sharing keeps under [`SHARING_MARGIN`] of what it removes.
    /// `"cycle"`: sharing takes the unit's stage past the cycle a core states,
    /// and the unit apart fits it.
    pub because: &'static str,
    /// The unit's longest stage, in gate delays, with the class shared.
    pub stage: f64,
}

pub fn merge_unit_with(design: &mut HwDesign, name: &str, members: &[usize], policy: Sharing)
                       -> MergedUnit {
    match policy {
        Sharing::Always => return merge_unit_apart(design, name, members, policy, &[]),
        Sharing::Never => return merge_unit_apart(design, name, members, policy, &UnitClass::ALL),
        Sharing::WhenItPays => {}
    }
    // Each class that shares is asked what the unit would be without it, and
    // the one that keeps least of what it removes is put back apart, until
    // every share left clears the margin. Deciding node by node, as
    // `Merger::bind` does, sees the mux a share adds and not what else the
    // unit loses to it -- the shifter beside a rotator that no longer reads
    // the same value.
    let mut apart: Vec<UnitClass> = Vec::new();
    let mut kept_apart: Vec<KeptApart> = Vec::new();
    loop {
        let mut unit = merge_unit_apart(design, name, members, policy, &apart);
        let sharing: Vec<UnitClass> = UnitClass::ALL
            .iter()
            .copied()
            .filter(|class| {
                unit.instances.iter().any(|instance| instance.class == class.name() && instance.nodes > 1)
            })
            .collect();
        let of_class = |unit: &MergedUnit, class: UnitClass| -> f64 {
            unit.area_by_operator
                .iter()
                .filter(|(operator, _)| class.operators().contains(&operator.as_str()))
                .map(|(_, area)| *area)
                .sum()
        };
        let mut worst: Option<(f64, UnitClass, KeptApart)> = None;
        for class in sharing {
            let mut without = apart.clone();
            without.push(class);
            let alone = merge_unit_apart(design, name, members, policy, &without);
            let saves = alone.area_merged - unit.area_merged;
            let removes = of_class(&alone, class) - of_class(&unit, class);
            let kept = if removes > 0.0 { saves / removes } else if saves > 0.0 { 1.0 } else { 0.0 };
            if kept < SHARING_MARGIN && worst.as_ref().map_or(true, |(least, _, _)| kept < *least) {
                worst = Some((kept, class, KeptApart {
                    class: class.name(),
                    removes,
                    saves,
                    because: "area",
                    stage: stage_of(&design.graph, &unit),
                }));
            }
        }
        // ⚠️ Then time, where there is a cycle to hold it to. Sharing puts a
        // mux before the operator and another after it, and every
        // instruction the unit runs pays for both. Only a cycle a CORE states
        // (`(cycle (gates N))`) is held: the planner's own -- two adders of
        // the widest result -- is a rule for grouping, and a share is not
        // refused for crossing a rule.
        if worst.is_none() {
            if let Some(cycle) = design.cycle {
                let stage = stage_of(&design.graph, &unit);
                if stage > cycle {
                    // Of the shares whose undoing brings the unit inside the
                    // cycle, the one that costs least area to undo.
                    let mut cheapest: Option<(f64, UnitClass, KeptApart)> = None;
                    for class in UnitClass::ALL.iter().copied().filter(|class| {
                        unit.instances.iter().any(|i| i.class == class.name() && i.nodes > 1)
                    }) {
                        let mut without = apart.clone();
                        without.push(class);
                        let alone = merge_unit_apart(design, name, members, policy, &without);
                        if stage_of(&design.graph, &alone) > cycle {
                            continue;
                        }
                        let costs = alone.area_merged - unit.area_merged;
                        if cheapest.as_ref().map_or(true, |(least, _, _)| costs < *least) {
                            let removes = of_class(&alone, class) - of_class(&unit, class);
                            cheapest = Some((costs, class, KeptApart {
                                class: class.name(),
                                removes,
                                saves: costs,
                                because: "cycle",
                                stage,
                            }));
                        }
                    }
                    worst = cheapest.map(|(costs, class, why)| (costs, class, why));
                }
            }
        }
        match worst {
            Some((_, class, why)) => {
                apart.push(class);
                kept_apart.push(why);
            }
            None => {
                unit.kept_apart = kept_apart;
                return unit;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Units over effects.
//
// A value has one result; an instruction stated as effects has several -- a
// register it writes, the program counter if a condition holds, a store's
// address and value, a load's address, a flag word. Each becomes a SLOT of
// the unit it joins, named by what it is and not by which instruction drives
// it, so `ADD`'s result and `ADDS`'s are one slot and one adder can drive
// both. The merger is the one above: it shares operators between nodes of
// different members, never two of one member, whatever output they reach.

/// A member of a unit with slots: a value datapath, or an instruction stated
/// as effects, by its index in `HwDesign::datapaths` or `::behaviors`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberRef {
    Value(usize),
    Effect(usize),
}

impl MemberRef {
    pub fn mnemonic<'a>(&self, design: &'a HwDesign) -> &'a str {
        match *self {
            MemberRef::Value(i) => &design.datapaths[i].mnemonic,
            MemberRef::Effect(i) => &design.behaviors[i].mnemonic,
        }
    }

    pub fn latency(&self, design: &HwDesign) -> u32 {
        match *self {
            MemberRef::Value(i) => design.datapaths[i].latency,
            MemberRef::Effect(i) => design.behaviors[i].latency,
        }
    }
}

/// Where a slot's value comes from in one member: what a checker compares the
/// unit against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotSource {
    /// A value datapath's result.
    Result,
    /// A load's address.
    LoadAddr,
    /// The `k`-th effect's value, guard or address.
    Value(usize),
    Guard(usize),
    Addr(usize),
}

/// The slots one member drives, in its effects' order: `(slot, width, node,
/// where it came from)`. A register write is `w0`, `w1`, ...; the program
/// counter `pc`; a flag word `s_<name>`; a store `st0_addr` and `st0_value`;
/// a load's address `ld_addr`. A guarded one has `<slot>_en` beside it.
pub fn member_slots(design: &HwDesign, member: MemberRef) -> Vec<(String, u32, NodeId, SlotSource)> {
    match member {
        MemberRef::Value(i) => {
            let datapath = &design.datapaths[i];
            let root = *datapath.root.as_ref().expect("only a datapath with a circuit joins a unit");
            vec![("w0".to_string(), datapath.output_width, root, SlotSource::Result)]
        }
        MemberRef::Effect(i) => {
            let behavior = &design.behaviors[i];
            let effects = behavior.effects.as_ref().expect("only an instruction with effects joins");
            let mut slots = Vec::new();
            if let Some(load) = &behavior.load {
                slots.push(("ld_addr".to_string(), design.graph.width(load.addr), load.addr, SlotSource::LoadAddr));
            }
            let (mut writes, mut stores) = (0, 0);
            for (k, effect) in effects.iter().enumerate() {
                let base = match &effect.kind {
                    EffectKind::Set { .. } => {
                        writes += 1;
                        format!("w{}", writes - 1)
                    }
                    EffectKind::SetPc => "pc".to_string(),
                    EffectKind::SetState { name } => format!("s_{name}"),
                    EffectKind::Store => {
                        stores += 1;
                        format!("st{}", stores - 1)
                    }
                };
                let width = design.graph.width(effect.value);
                if let Some(addr) = effect.addr {
                    slots.push((format!("{base}_addr"), design.graph.width(addr), addr, SlotSource::Addr(k)));
                    slots.push((format!("{base}_value"), width, effect.value, SlotSource::Value(k)));
                } else {
                    slots.push((base.clone(), width, effect.value, SlotSource::Value(k)));
                }
                if let Some(guard) = effect.guard {
                    slots.push((format!("{base}_en"), 1, guard, SlotSource::Guard(k)));
                }
            }
            slots
        }
    }
}

/// A unit whose members may write registers, the program counter, memory and
/// state: one output per slot.
pub struct SlotUnit {
    pub name: String,
    pub members: Vec<MemberRef>,
    pub select_width: u32,
    pub inputs: Vec<(String, u32)>,
    /// `(slot, width, node)`. A slot `X_en` says whether `X` is written: it
    /// exists where some member guards `X` or some member does not drive it.
    pub slots: Vec<(String, u32, NodeId)>,
    /// Per member, per slot it drives: where the value came from.
    pub sources: Vec<Vec<(String, SlotSource)>>,
    pub latency: u32,
    pub instances: Vec<InstanceReport>,
    pub area_identical: f64,
    pub area_merged: f64,
    pub depth_merged: f64,
    pub area_by_operator: Vec<(String, f64)>,
    pub kept_apart: Vec<KeptApart>,
}

/// Merge members with slots into one unit, sharing as `Sharing::WhenItPays`
/// does for values -- node by node, then class by class under
/// [`SHARING_MARGIN`].
pub fn merge_slot_unit(design: &mut HwDesign, name: &str, members: &[MemberRef]) -> SlotUnit {
    let mut apart: Vec<UnitClass> = Vec::new();
    let mut kept_apart: Vec<KeptApart> = Vec::new();
    loop {
        let mut unit = merge_slots_apart(design, name, members, &apart);
        let of_class = |unit: &SlotUnit, class: UnitClass| -> f64 {
            unit.area_by_operator
                .iter()
                .filter(|(operator, _)| class.operators().contains(&operator.as_str()))
                .map(|(_, area)| *area)
                .sum()
        };
        let mut worst: Option<(f64, UnitClass, KeptApart)> = None;
        let sharing: Vec<UnitClass> = UnitClass::ALL
            .iter()
            .copied()
            .filter(|class| unit.instances.iter().any(|i| i.class == class.name() && i.nodes > 1))
            .collect();
        for class in sharing {
            let mut without = apart.clone();
            without.push(class);
            let alone = merge_slots_apart(design, name, members, &without);
            let saves = alone.area_merged - unit.area_merged;
            let removes = of_class(&alone, class) - of_class(&unit, class);
            let kept = if removes > 0.0 { saves / removes } else if saves > 0.0 { 1.0 } else { 0.0 };
            if kept < SHARING_MARGIN && worst.as_ref().map_or(true, |(least, _, _)| kept < *least) {
                worst = Some((kept, class, KeptApart {
                    class: class.name(),
                    removes,
                    saves,
                    because: "area",
                    stage: unit.depth_merged,
                }));
            }
        }
        match worst {
            Some((_, class, why)) => {
                apart.push(class);
                kept_apart.push(why);
            }
            None => {
                unit.kept_apart = kept_apart;
                return unit;
            }
        }
    }
}

fn merge_slots_apart(design: &mut HwDesign, name: &str, members: &[MemberRef], apart: &[UnitClass])
                     -> SlotUnit {
    let per_member: Vec<Vec<(String, u32, NodeId, SlotSource)>> =
        members.iter().map(|member| member_slots(design, *member)).collect();
    // The slots, in the order members first drive them, each at its widest.
    let mut slots: Vec<(String, u32)> = Vec::new();
    for own in &per_member {
        for (slot, width, _, _) in own {
            match slots.iter_mut().find(|(known, _)| known == slot) {
                Some((_, widest)) => *widest = (*widest).max(*width),
                None => slots.push((slot.clone(), *width)),
            }
        }
    }
    // A slot some member does not drive, or drives under a guard, says so.
    let needs_enable: Vec<String> = slots
        .iter()
        .filter(|(slot, _)| !slot.ends_with("_en"))
        .filter(|(slot, _)| {
            per_member.iter().any(|own| !own.iter().any(|(s, _, _, _)| s == slot))
                || slots.iter().any(|(s, _)| *s == format!("{slot}_en"))
        })
        .map(|(slot, _)| slot.clone())
        .collect();
    for slot in &needs_enable {
        let enable = format!("{slot}_en");
        if !slots.iter().any(|(s, _)| *s == enable) {
            slots.push((enable, 1));
        }
    }

    let mut inputs: Vec<(String, u32)> = Vec::new();
    let mut add_input = |name: &str, width: u32, inputs: &mut Vec<(String, u32)>| {
        match inputs.iter_mut().find(|(known, _)| known == name) {
            Some((_, widest)) => *widest = (*widest).max(width),
            None => inputs.push((name.to_string(), width)),
        }
    };
    for member in members {
        match *member {
            MemberRef::Value(i) => {
                for (input, width) in design.datapaths[i].inputs.clone() {
                    add_input(&input, width, &mut inputs);
                }
            }
            MemberRef::Effect(i) => {
                for (input, width) in design.behaviors[i].inputs.clone() {
                    add_input(&input, width, &mut inputs);
                }
                if let Some(load) = &design.behaviors[i].load {
                    add_input(LOAD_INPUT, load.width, &mut inputs);
                }
            }
        }
    }

    let graph = &mut design.graph;
    let ports: HashMap<String, u32> = inputs.iter().cloned().collect();
    let mut through = HashMap::new();
    // Every member drives every slot: its own value, its own guard (or one
    // where it always writes), and zero where it writes nothing there.
    let one = graph.konst(1, 1);
    let roots: Vec<Vec<NodeId>> = per_member
        .iter()
        .map(|own| {
            slots
                .iter()
                .map(|(slot, width)| {
                    let found = own.iter().find(|(s, _, _, _)| s == slot).map(|(_, _, node, _)| *node);
                    match found {
                        Some(node) => graph.through_ports(node, &ports, &mut through),
                        None => match slot.strip_suffix("_en") {
                            Some(base) if own.iter().any(|(s, _, _, _)| s == base) => one,
                            _ => graph.konst(0, *width),
                        },
                    }
                })
                .collect()
        })
        .collect();
    let select_width = if members.len() > 1 { ceil_log2(members.len() as u32) } else { 0 };
    let select = (select_width > 0).then(|| graph.input(SELECT_INPUT, select_width));
    let zero = graph.konst(0, 1);

    let mut users: HashMap<NodeId, Vec<usize>> = HashMap::new();
    for (code, own) in roots.iter().enumerate() {
        for id in graph.cone(own) {
            users.entry(id).or_default().push(code);
        }
    }
    let every: Vec<NodeId> = roots.iter().flatten().copied().collect();
    let cone = graph.cone(&every);
    let mut low_only: HashSet<NodeId> =
        cone.iter().copied().filter(|id| graph.node(*id).op == HwOp::AddSub).collect();
    for id in &cone {
        let node = graph.node(*id);
        for arg in &node.args {
            let sum = graph.width(*arg) - 1;
            if !(node.op == HwOp::Slice && node.value as u32 + node.width <= sum) {
                low_only.remove(arg);
            }
        }
    }
    for root in &every {
        low_only.remove(root);
    }
    let mut merger = Merger {
        graph,
        select,
        select_width,
        users,
        binding: HashMap::new(),
        low_only,
        zero,
        policy: Sharing::WhenItPays,
        apart: apart.to_vec(),
        instances: Vec::new(),
        frontier: HashMap::new(),
        outputs: Vec::new(),
        rebuilt: HashMap::new(),
    };
    // Per slot, the mux over what each member drives there.
    let muxed = |merger: &mut Merger, values: &[Vec<NodeId>]| -> Vec<NodeId> {
        (0..slots.len())
            .map(|s| {
                let mut groups: Vec<(NodeId, Vec<usize>)> = Vec::new();
                for (code, own) in values.iter().enumerate() {
                    let value = merger.graph.zext(own[s], slots[s].1);
                    match groups.iter_mut().find(|(known, _)| *known == value) {
                        Some((_, codes)) => codes.push(code),
                        None => groups.push((value, vec![code])),
                    }
                }
                merger.choose(groups)
            })
            .collect()
    };
    let unmerged = muxed(&mut merger, &roots);
    let (area_identical, _) = merger.graph.cone_cost(&unmerged);
    merger.bind(&cone);
    merger.outputs = vec![None; merger.instances.len()];
    let rebuilt: Vec<Vec<NodeId>> =
        roots.iter().map(|own| own.iter().map(|root| merger.rebuild(*root)).collect()).collect();
    let outputs = muxed(&mut merger, &rebuilt);
    let (area_merged, depth_merged) = merger.graph.cone_cost(&outputs);
    let area_by_operator = merger.graph.cone_area_by_operator(&outputs);
    let instances = merger
        .instances
        .iter()
        .map(|instance| InstanceReport {
            class: instance.class.name(),
            width: instance.width,
            nodes: instance.bound.len(),
            members: instance.members.iter().copied().collect(),
        })
        .collect();
    SlotUnit {
        name: name.to_string(),
        members: members.to_vec(),
        select_width,
        inputs,
        slots: slots.iter().zip(&outputs).map(|((slot, width), node)| (slot.clone(), *width, *node)).collect(),
        sources: per_member
            .iter()
            .map(|own| own.iter().map(|(slot, _, _, source)| (slot.clone(), source.clone())).collect())
            .collect(),
        latency: members.iter().map(|member| member.latency(design)).max().unwrap_or(1),
        instances,
        area_identical,
        area_merged,
        depth_merged,
        area_by_operator,
        kept_apart: Vec::new(),
    }
}

/// AXIS's own grouping with effects in it: its value units as they are, and
/// every instruction stated as effects joining the one its class and latency
/// say -- the unit it names, else `lsu` for one that touches memory, `br` for
/// one that sets the program counter, `alu` otherwise. An effect `alu` at an
/// existing ALU's latency joins that ALU, which is the point: `ADDS` beside
/// `ADD`, one adder for both.
pub fn plan_slot_units(design: &mut HwDesign) -> Vec<(String, Vec<MemberRef>)> {
    let (_, units) = build_units(design);
    let mut groups: Vec<(String, u32, Vec<MemberRef>)> = units
        .iter()
        .map(|unit| {
            (unit.name.clone(), unit.latency, unit.members.iter().map(|m| MemberRef::Value(*m)).collect())
        })
        .collect();
    for (i, behavior) in design.behaviors.iter().enumerate() {
        let Ok(effects) = &behavior.effects else { continue };
        let class = if !behavior.unit.is_empty() {
            behavior.unit.clone()
        } else if behavior.load.is_some() || effects.iter().any(|e| e.kind == EffectKind::Store) {
            "lsu".to_string()
        } else if effects.iter().any(|e| e.kind == EffectKind::SetPc) {
            "br".to_string()
        } else {
            "alu".to_string()
        };
        let latency = behavior.latency;
        // A group's class is its name without the latency the planner puts
        // after it: `alu_l2` is an `alu`.
        let class_of = |name: &str| -> String {
            match name.rsplit_once("_l") {
                Some((base, digits)) if digits.chars().all(|c| c.is_ascii_digit()) => base.to_string(),
                _ => name.to_string(),
            }
        };
        let joined = groups.iter_mut().find(|(name, l, _)| *l == latency && class_of(name) == class);
        match joined {
            Some((_, _, members)) => members.push(MemberRef::Effect(i)),
            None => {
                let mut name = if latency == 1 { class.clone() } else { format!("{class}_l{latency}") };
                while groups.iter().any(|(known, _, _)| *known == name) {
                    name.push('x');
                }
                groups.push((name, latency, vec![MemberRef::Effect(i)]));
            }
        }
    }
    groups.into_iter().map(|(name, _, members)| (name, members)).collect()
}

/// A unit's longest stage, in gate delays, cut into the stages its latency
/// gives it.
fn stage_of(graph: &HwGraph, unit: &MergedUnit) -> f64 {
    schedule(graph, unit.root, unit.latency.saturating_sub(1)).stage_delay
}

fn merge_unit_apart(design: &mut HwDesign, name: &str, members: &[usize], policy: Sharing,
                    apart: &[UnitClass]) -> MergedUnit {
    let roots: Vec<NodeId> = members
        .iter()
        .map(|member| {
            *design.datapaths[*member]
                .root
                .as_ref()
                .expect("only a datapath with a circuit joins a unit")
        })
        .collect();
    let output_width = members
        .iter()
        .map(|member| design.datapaths[*member].output_width)
        .max()
        .unwrap_or(1);
    let mut inputs: Vec<(String, u32)> = Vec::new();
    for member in members {
        for (name, width) in &design.datapaths[*member].inputs {
            match inputs.iter_mut().find(|(known, _)| known == name) {
                Some((_, widest)) => *widest = (*widest).max(*width),
                None => inputs.push((name.clone(), *width)),
            }
        }
    }
    let graph = &mut design.graph;
    // One port is one wire, whatever width each member reads of it.
    let ports: HashMap<String, u32> = inputs.iter().cloned().collect();
    let mut through = HashMap::new();
    let roots: Vec<NodeId> =
        roots.into_iter().map(|root| graph.through_ports(root, &ports, &mut through)).collect();
    let select_width = if members.len() > 1 { ceil_log2(members.len() as u32) } else { 0 };
    let select = (select_width > 0).then(|| graph.input(SELECT_INPUT, select_width));
    let zero = graph.konst(0, 1);

    let mut users: HashMap<NodeId, Vec<usize>> = HashMap::new();
    let mut area_alone = 0.0;
    let mut depth_slowest_member: f64 = 0.0;
    for (code, root) in roots.iter().enumerate() {
        for id in graph.cone(&[*root]) {
            users.entry(id).or_default().push(code);
        }
        let (area, depth) = graph.cone_cost(&[*root]);
        area_alone += area;
        depth_slowest_member = depth_slowest_member.max(depth);
    }
    let cone = graph.cone(&roots);
    let (area_cone, _) = graph.cone_cost(&roots);
    // An adder's carry is read by anything that is not a slice of its sum.
    let mut low_only: HashSet<NodeId> = cone
        .iter()
        .copied()
        .filter(|id| graph.node(*id).op == HwOp::AddSub)
        .collect();
    for id in &cone {
        let node = graph.node(*id);
        for arg in &node.args {
            let sum = graph.width(*arg) - 1;
            if !(node.op == HwOp::Slice && node.value as u32 + node.width <= sum) {
                low_only.remove(arg);
            }
        }
    }
    for root in &roots {
        low_only.remove(root);
    }

    let mut merger = Merger {
        graph,
        select,
        select_width,
        users,
        binding: HashMap::new(),
        low_only,
        zero,
        policy,
        apart: apart.to_vec(),
        instances: Vec::new(),
        frontier: HashMap::new(),
        outputs: Vec::new(),
        rebuilt: HashMap::new(),
    };
    // The result mux over the circuits as they stand: what the unit costs
    // with no operator shared, which is what merging has to beat.
    let result = |merger: &mut Merger, values: Vec<NodeId>| -> NodeId {
        let mut groups: Vec<(NodeId, Vec<usize>)> = Vec::new();
        for (code, value) in values.into_iter().enumerate() {
            let value = merger.graph.zext(value, output_width);
            match groups.iter_mut().find(|(known, _)| *known == value) {
                Some((_, codes)) => codes.push(code),
                None => groups.push((value, vec![code])),
            }
        }
        merger.choose(groups)
    };
    let unmerged = result(&mut merger, roots.clone());
    let (area_identical, _) = merger.graph.cone_cost(&[unmerged]);

    merger.bind(&cone);
    merger.outputs = vec![None; merger.instances.len()];
    let values: Vec<NodeId> = roots.iter().map(|root| merger.rebuild(*root)).collect();
    let root = result(&mut merger, values);
    let (area_merged, depth_merged) = merger.graph.cone_cost(&[root]);
    let area_by_operator = merger.graph.cone_area_by_operator(&[root]);

    let instances = merger
        .instances
        .iter()
        .map(|instance| InstanceReport {
            class: instance.class.name(),
            width: instance.width,
            nodes: instance.bound.len(),
            members: instance.members.iter().copied().collect(),
        })
        .collect();
    let latency = members
        .iter()
        .map(|member| design.datapaths[*member].latency)
        .max()
        .unwrap_or(1);
    MergedUnit {
        name: name.to_string(),
        latency,
        members: members.to_vec(),
        select_width,
        inputs,
        output_width,
        root,
        instances,
        area_separate: area_alone + (area_identical - area_cone),
        area_identical,
        area_merged,
        area_by_operator,
        kept_apart: Vec::new(),
        depth_slowest_member,
        depth_merged,
    }
}

/// Which datapaths go in which unit, and where the answer came from.
pub struct UnitPlan {
    /// `declared` when the description's own `(unit ...)` tags were used,
    /// `derived` when the grouping was worked out here.
    pub grouping: &'static str,
    pub groups: Vec<(String, Vec<usize>)>,
}

/// How long a cycle is taken to be, when a description does not say: two
/// adders of the widest result. An ALU operation and the muxes around it fit;
/// a multiplier does not.
pub fn cycle_budget(design: &HwDesign) -> f64 {
    if let Some(cycle) = design.cycle {
        return cycle;
    }
    let widest = design
        .datapaths
        .iter()
        .filter(|datapath| datapath.root.is_ok())
        .map(|datapath| datapath.output_width)
        .max()
        .unwrap_or(32);
    2.0 * adder_cost(widest).1
}

pub fn plan_units(design: &mut HwDesign) -> UnitPlan {
    let built: Vec<usize> = (0..design.datapaths.len())
        .filter(|index| design.datapaths[*index].root.is_ok())
        .collect();
    let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
    let mut place = |groups: &mut Vec<(String, Vec<usize>)>, name: &str, index: usize| {
        match groups.iter_mut().find(|(known, _)| known == name) {
            Some((_, members)) => members.push(index),
            None => groups.push((name.to_string(), vec![index])),
        }
    };
    // A description that tags every instruction has already decided, and a
    // core that names those units is read by the timing model. Second-guessing
    // it here would make two answers to one question.
    if !built.is_empty() && built.iter().all(|index| !design.datapaths[*index].unit.is_empty()) {
        for index in &built {
            let name = design.datapaths[*index].unit.clone();
            place(&mut groups, &name, *index);
        }
        return UnitPlan { grouping: "declared", groups };
    }

    let budget = cycle_budget(design);
    for index in &built {
        let root = *design.datapaths[*index].root.as_ref().unwrap();
        let (_, depth) = design.graph.cone_cost(&[root]);
        let has = |op: HwOp| {
            design.graph.cone(&[root]).iter().any(|id| design.graph.node(*id).op == op)
        };
        let name = if depth <= budget {
            "alu"
        } else if has(HwOp::DivRem) {
            "div"
        } else if has(HwOp::Mul) || has(HwOp::MulWide) {
            "mul"
        } else {
            "slow"
        };
        place(&mut groups, name, *index);
    }
    // Join two slow units when one merged unit is smaller than the two apart.
    // The ALU is left out: joining it to anything slow would put a
    // single-cycle instruction behind a multi-cycle operator.
    loop {
        let mut best: Option<(f64, usize, usize)> = None;
        for a in 0..groups.len() {
            for b in a + 1..groups.len() {
                if groups[a].0 == "alu" || groups[b].0 == "alu" {
                    continue;
                }
                let apart = merge_unit(design, "", &groups[a].1).area_merged
                    + merge_unit(design, "", &groups[b].1).area_merged;
                let mut both = groups[a].1.clone();
                both.extend(groups[b].1.iter().copied());
                both.sort_unstable();
                let gain = apart - merge_unit(design, "", &both).area_merged;
                if gain > 0.0 && best.map_or(true, |(most, _, _)| gain > most) {
                    best = Some((gain, a, b));
                }
            }
        }
        let Some((_, a, b)) = best else { break };
        let (name, members) = groups.remove(b);
        groups[a].0.push_str(&name);
        groups[a].1.extend(members);
        groups[a].1.sort_unstable();
    }
    UnitPlan { grouping: "derived", groups }
}

/// One latency per unit. A unit is cut into as many stages as its
/// instructions take cycles (H3), so two instructions that take different
/// numbers of cycles cannot be one unit without one of them contradicting the
/// description -- and the cycle simulator, which charges what it declares.
/// The latency most of a group shares keeps the group's name; the others are
/// named for theirs.
fn split_by_latency(design: &HwDesign, groups: Vec<(String, Vec<usize>)>)
                    -> Vec<(String, Vec<usize>)> {
    let mut split = Vec::new();
    for (name, members) in groups {
        let mut by_latency: Vec<(u32, Vec<usize>)> = Vec::new();
        for member in members {
            let latency = design.datapaths[member].latency;
            match by_latency.iter_mut().find(|(known, _)| *known == latency) {
                Some((_, same)) => same.push(member),
                None => by_latency.push((latency, vec![member])),
            }
        }
        let most = by_latency.iter().map(|(_, same)| same.len()).max().unwrap_or(0);
        let keeps = by_latency.iter().position(|(_, same)| same.len() == most);
        for (index, (latency, same)) in by_latency.into_iter().enumerate() {
            let name = if Some(index) == keeps { name.clone() } else { format!("{name}_l{latency}") };
            split.push((name, same));
        }
    }
    split
}

/// Where the registers of a pipelined unit go.
pub struct Schedule {
    /// How many registers lie on every path from an input to the result.
    pub registers: u32,
    /// The stage in which each node's result is ready.
    pub stage: HashMap<NodeId, u32>,
    /// Registers INSIDE a node: a multiplier or a divider spanning stages.
    pub cuts: HashMap<NodeId, u32>,
    /// The longest stage, under the cost model.
    pub stage_delay: f64,
}

impl Schedule {
    /// The stage a node's inputs must all be in.
    pub fn input_stage(&self, id: NodeId) -> u32 {
        self.stage[&id] - self.cuts.get(&id).copied().unwrap_or(0)
    }
}

/// Place `registers` pipeline registers under `root`: as soon as possible,
/// each stage filled to an even share of the total depth. A node that cannot
/// be cut starts a new stage when it would overrun the one it is in; a
/// multiplier or a divider takes registers inside itself.
///
/// ⚠️ Retiming only. No node changes, so the unit computes exactly what the
/// unpipelined one does, `registers` cycles later -- which is what
/// `hw_units_check.py` holds it to, a new instruction every cycle.
pub fn schedule(graph: &HwGraph, root: NodeId, registers: u32) -> Schedule {
    schedule_roots(graph, &[root], registers)
}

/// The same for a unit with several outputs: one cut through all of them, so
/// every output leaves after the same number of registers.
pub fn schedule_roots(graph: &HwGraph, roots: &[NodeId], registers: u32) -> Schedule {
    let (_, depth) = graph.cone_cost(roots);
    let share = (depth / (registers as f64 + 1.0)).max(1.0);
    let mut stage: HashMap<NodeId, u32> = HashMap::new();
    let mut time: HashMap<NodeId, f64> = HashMap::new();
    let mut cuts = HashMap::new();
    let mut stage_delay: f64 = 0.0;
    for id in graph.cone(roots) {
        let node = graph.node(id);
        // A constant is the same in every stage and holds nothing back.
        let args: Vec<NodeId> = node
            .args
            .iter()
            .copied()
            .filter(|arg| graph.node(*arg).op != HwOp::Const)
            .collect();
        let enters = args.iter().map(|arg| stage[arg]).max().unwrap_or(0);
        let start = args
            .iter()
            .filter(|arg| stage[*arg] == enters)
            .map(|arg| time[arg])
            .fold(0.0, f64::max);
        let (_, delay) = graph.node_cost(id);
        let cuttable = matches!(node.op, HwOp::Mul | HwOp::MulWide | HwOp::DivRem);
        let (leaves, ready) = if cuttable {
            let inside = (((start + delay) / share - 1e-9).floor().max(0.0) as u32)
                .min(registers - enters);
            if inside > 0 {
                cuts.insert(id, inside);
                stage_delay = stage_delay.max(((start + delay) / (inside as f64 + 1.0)).max(start));
            }
            (enters + inside, (start + delay - inside as f64 * share).max(0.0))
        } else if start > 0.0 && start + delay > share + 1e-9 && enters < registers {
            (enters + 1, delay)
        } else {
            (enters, start + delay)
        };
        if !cuts.contains_key(&id) {
            stage_delay = stage_delay.max(ready);
        }
        stage.insert(id, leaves);
        time.insert(id, ready);
    }
    Schedule { registers, stage, cuts, stage_delay }
}

/// One unit of a plan handed in from outside: which instructions, and how
/// eagerly their operators are shared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposedUnit {
    pub name: String,
    pub members: Vec<String>,
    pub sharing: Sharing,
}

/// Read a plan:
///
/// ```text
/// (hw-plan
///   (unit alu (sharing when-it-pays) (members ADD SUB XOR))
///   (unit muldiv (sharing always) (members MUL DIV)))
/// ```
///
/// This is the door a proposer comes through -- a search, a learned cost
/// model, a language model. It is deliberately narrow: a plan says which
/// instructions share a unit and how hard to share, and nothing about what
/// any of them computes.
pub fn parse_plan(text: &str) -> Result<Vec<ProposedUnit>, String> {
    use crate::semantics::{parse_formal_semantics, SemanticExpr};
    let atom = |expr: &SemanticExpr| match expr {
        SemanticExpr::Atom(text) => Some(text.clone()),
        SemanticExpr::List(_) => None,
    };
    let tree = parse_formal_semantics(text).map_err(|error| format!("hw-plan: {error}"))?;
    let SemanticExpr::List(items) = tree else {
        return Err("hw-plan: expected `(hw-plan (unit ...) ...)`".to_string());
    };
    if items.first().and_then(atom).as_deref() != Some("hw-plan") {
        return Err("hw-plan: expected `(hw-plan (unit ...) ...)`".to_string());
    }
    let mut units: Vec<ProposedUnit> = Vec::new();
    for item in &items[1..] {
        let SemanticExpr::List(parts) = item else {
            return Err("hw-plan: each entry is `(unit <name> ...)`".to_string());
        };
        let (Some("unit"), Some(name)) =
            (parts.first().and_then(atom).as_deref(), parts.get(1).and_then(atom))
        else {
            return Err("hw-plan: each entry is `(unit <name> ...)`".to_string());
        };
        if !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
            return Err(format!("hw-plan: unit name `{name}` is not letters, digits and `_`"));
        }
        if units.iter().any(|unit| unit.name == name) {
            return Err(format!("hw-plan: unit `{name}` appears twice"));
        }
        let mut unit = ProposedUnit { name, members: Vec::new(), sharing: Sharing::WhenItPays };
        for clause in &parts[2..] {
            let SemanticExpr::List(fields) = clause else {
                return Err(format!("hw-plan: unit `{}` has a bare `{clause:?}`", unit.name));
            };
            let words: Option<Vec<String>> = fields.iter().map(atom).collect();
            let words = words.ok_or_else(|| format!("hw-plan: unit `{}` nests a list", unit.name))?;
            match words.split_first() {
                Some((head, rest)) if head == "members" => unit.members.extend(rest.iter().cloned()),
                Some((head, [policy])) if head == "sharing" => {
                    unit.sharing = match policy.as_str() {
                        "when-it-pays" => Sharing::WhenItPays,
                        "always" => Sharing::Always,
                        "never" => Sharing::Never,
                        other => {
                            return Err(format!(
                                "hw-plan: sharing is `when-it-pays`, `always` or `never`, not `{other}`"
                            ))
                        }
                    };
                }
                _ => return Err(format!("hw-plan: unit `{}` has an unknown clause", unit.name)),
            }
        }
        units.push(unit);
    }
    Ok(units)
}

/// A plan as text, in the form [`parse_plan`] reads.
pub fn render_plan(design: &HwDesign, units: &[MergedUnit]) -> String {
    let mut out = String::from("(hw-plan\n");
    for unit in units {
        let members: Vec<&str> =
            unit.members.iter().map(|member| design.datapaths[*member].mnemonic.as_str()).collect();
        out.push_str(&format!(
            "  (unit {} (sharing when-it-pays)\n    (members {}))\n",
            unit.name,
            members.join(" ")
        ));
    }
    out.push_str(")\n");
    out
}

/// Plan the units and merge each -- by AXIS's own rules, or as proposed.
///
/// ⚠️ A proposed plan is checked for what would make it a different MACHINE,
/// and refused by name: an instruction with no circuit, an instruction in two
/// units, an instruction left out, two latencies in one unit. It is never
/// checked for being good. A bad plan builds a large, slow, correct unit, and
/// `emit-hw-json` says how large and how slow -- which is the answer a search
/// is asking for.
pub fn build_units_with(design: &mut HwDesign, proposed: Option<&[ProposedUnit]>)
                        -> Result<(&'static str, Vec<MergedUnit>), String> {
    let Some(proposed) = proposed else {
        return Ok(build_units(design));
    };
    let mut placed: HashMap<usize, &str> = HashMap::new();
    let mut groups: Vec<(&ProposedUnit, Vec<usize>)> = Vec::new();
    for unit in proposed {
        if unit.members.is_empty() {
            return Err(format!("hw-plan: unit `{}` has no members", unit.name));
        }
        let mut members = Vec::new();
        for mnemonic in &unit.members {
            let Some(index) = design.datapaths.iter().position(|one| &one.mnemonic == mnemonic)
            else {
                return Err(format!("hw-plan: `{mnemonic}` is not an instruction with semantics"));
            };
            if let Err(reason) = &design.datapaths[index].root {
                return Err(format!("hw-plan: `{mnemonic}` has no circuit -- {reason}"));
            }
            if let Some(other) = placed.insert(index, &unit.name) {
                return Err(format!(
                    "hw-plan: `{mnemonic}` is in `{other}` and in `{}`",
                    unit.name
                ));
            }
            members.push(index);
        }
        let latencies: HashSet<u32> =
            members.iter().map(|member| design.datapaths[*member].latency).collect();
        if latencies.len() > 1 {
            let mut listed: Vec<u32> = latencies.into_iter().collect();
            listed.sort_unstable();
            return Err(format!(
                "hw-plan: unit `{}` mixes instructions of {listed:?} cycles; a unit has one latency",
                unit.name
            ));
        }
        members.sort_unstable();
        groups.push((unit, members));
    }
    let missing: Vec<&str> = design
        .datapaths
        .iter()
        .enumerate()
        .filter(|(index, one)| one.root.is_ok() && !placed.contains_key(index))
        .map(|(_, one)| one.mnemonic.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(format!(
            "hw-plan: {} instruction(s) with a circuit are in no unit: {}",
            missing.len(),
            missing[..missing.len().min(6)].join(", ")
        ));
    }
    let units = groups
        .iter()
        .map(|(unit, members)| merge_unit_with(design, &unit.name, members, unit.sharing))
        .collect();
    Ok(("proposed", units))
}

/// Plan the units and merge each.
pub fn build_units(design: &mut HwDesign) -> (&'static str, Vec<MergedUnit>) {
    let mut plan = plan_units(design);
    plan.groups = split_by_latency(design, std::mem::take(&mut plan.groups));
    let units = plan
        .groups
        .iter()
        .map(|(name, members)| merge_unit(design, name, members))
        .collect();
    (plan.grouping, units)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw::lower_document;
    use crate::{parse_document, validate_document};

    /// A small deterministic generator: the tests need spread, not secrecy.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u128 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            // Corner values often enough to reach the carries and the signs.
            match self.0 % 8 {
                0 => 0,
                1 => u64::MAX as u128,
                2 => 1 << 63,
                3 => (self.0 >> 8) as u128 & 0xff,
                _ => self.0 as u128,
            }
        }
    }

    fn design(source: &str) -> HwDesign {
        let document = parse_document(source).unwrap();
        validate_document(&document).unwrap();
        lower_document(&document)
    }

    /// Every member, selected, computes what its own circuit computes --
    /// whatever sits on the operands it does not read.
    fn assert_units_match(design: &mut HwDesign, units: &[MergedUnit]) -> usize {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut compared = 0;
        for unit in units {
            for (code, member) in unit.members.iter().enumerate() {
                let datapath = &design.datapaths[*member];
                let own = *datapath.root.as_ref().unwrap();
                for _ in 0..24 {
                    let mut inputs: HashMap<String, u128> =
                        unit.inputs.iter().map(|(name, _)| (name.clone(), rng.next())).collect();
                    inputs.insert(SELECT_INPUT.to_string(), code as u128);
                    let want = design.graph.eval(own, &inputs);
                    let got = design.graph.eval(unit.root, &inputs);
                    assert_eq!(got, want, "{} in unit {}", datapath.mnemonic, unit.name);
                    compared += 1;
                }
            }
        }
        compared
    }

    #[test]
    fn rv64_merges_into_units_that_compute_what_their_members_do() {
        let mut design = design(include_str!("../examples/rv64i.axisl"));
        let built = design.datapaths.iter().filter(|datapath| datapath.root.is_ok()).count();
        assert!(built >= 60, "only {built} RV64 instructions have a circuit");
        let (grouping, units) = build_units(&mut design);
        assert_eq!(grouping, "derived");
        let names: Vec<&str> = units.iter().map(|unit| unit.name.as_str()).collect();
        // The remainder is read from the divider (`HwGraph::sub`), so `REM`
        // needs no multiplier and the two slow units have nothing to share.
        // Before that rewrite they joined into one `muldiv` -- correctly: the
        // divider's unit held a multiplier of its own.
        // The two `FCLASS` forms fit in a cycle and declare two, so they are a
        // unit of their own beside the ALU: one latency per unit.
        assert_eq!(names, ["alu", "alu_l2", "mul", "div"]);
        assert!(assert_units_match(&mut design, &units) > 1000);
        for unit in &units {
            // Merging never costs, and pays wherever there is an operator to
            // share -- which the two `FCLASS` forms, all masks and compares,
            // do not have.
            assert!(unit.area_merged <= unit.area_identical, "{}: merging cost area", unit.name);
            if unit.name != "alu_l2" {
                assert!(unit.area_merged < unit.area_identical, "{}: merging did not pay", unit.name);
            }
        }
    }

    #[test]
    fn the_alu_has_one_wide_adder_and_one_shifter() {
        let mut design = design(include_str!("../examples/rv64i.axisl"));
        let (_, units) = build_units(&mut design);
        let alu = units.iter().find(|unit| unit.name == "alu").unwrap();
        let of = |class: &str| -> Vec<u32> {
            alu.instances
                .iter()
                .filter(|instance| instance.class == class)
                .map(|instance| instance.width)
                .collect()
        };
        // ADD, SUB, SLT, SLTU, ADDI, ADDW, SUBW and the rest: one adder, and
        // the 32-bit forms ride its low half.
        assert_eq!(of("addsub"), vec![64]);
        assert_eq!(of("shift"), vec![64]);
    }

    #[test]
    fn a_schedule_puts_exactly_its_registers_on_every_path() {
        let mut design = design(include_str!("../examples/rv64i.axisl"));
        let (_, units) = build_units(&mut design);
        for unit in &units {
            assert!(unit.members.iter().all(|m| design.datapaths[*m].latency == unit.latency));
            let registers = unit.latency - 1;
            let plan = schedule(&design.graph, unit.root, registers);
            assert!(plan.stage[&unit.root] <= registers);
            for id in design.graph.cone(&[unit.root]) {
                let node = design.graph.node(id);
                // Stages only move forward, so every delay the emitter inserts
                // is a whole number of registers, never a negative one.
                for arg in &node.args {
                    if design.graph.node(*arg).op != HwOp::Const {
                        assert!(plan.stage[arg] <= plan.input_stage(id), "{} runs backwards", unit.name);
                    }
                }
                if plan.cuts.contains_key(&id) {
                    assert!(matches!(node.op, HwOp::Mul | HwOp::MulWide | HwOp::DivRem));
                }
            }
            if registers > 0 {
                let (_, depth) = design.graph.cone_cost(&[unit.root]);
                assert!(plan.stage_delay < depth, "{}: the cuts shortened nothing", unit.name);
            }
        }
    }

    #[test]
    fn its_own_plan_read_back_builds_the_same_units() {
        let mut first = design(include_str!("../examples/rv32i.axisl"));
        let (_, units) = build_units(&mut first);
        let text = render_plan(&first, &units);
        let proposed = parse_plan(&text).unwrap();
        let mut second = design(include_str!("../examples/rv32i.axisl"));
        let (grouping, again) = build_units_with(&mut second, Some(&proposed)).unwrap();
        assert_eq!(grouping, "proposed");
        let shape = |units: &[MergedUnit]| -> Vec<(String, Vec<usize>, u32)> {
            units.iter().map(|u| (u.name.clone(), u.members.clone(), u.area_merged as u32)).collect()
        };
        assert_eq!(shape(&units), shape(&again));
    }

    #[test]
    fn a_proposed_plan_may_be_bad_and_may_not_be_a_different_machine() {
        let source = include_str!("../examples/rv32i.axisl");
        let propose = |text: &str| {
            let mut design = design(source);
            let plan = parse_plan(text)?;
            build_units_with(&mut design, Some(&plan)).map(|(_, units)| (design, units))
        };
        let mut base = design(source);
        let (_, units) = build_units(&mut base);
        let own = render_plan(&base, &units);

        // Sharing everything that legally can be is a worse ALU by the cost
        // model, and it is built anyway and computes the same thing.
        let eager = own.replace("when-it-pays", "always");
        let (mut eager_design, eager_units) = propose(&eager).unwrap();
        assert!(assert_units_match(&mut eager_design, &eager_units) > 0);
        let instances = |units: &[MergedUnit]| -> usize {
            units.iter().map(|unit| unit.instances.len()).sum()
        };
        assert!(instances(&eager_units) <= instances(&units));

        // And sharing nothing: every operator its own, the same machine, and
        // exactly what hash-consing alone gives.
        let thrifty = own.replace("when-it-pays", "never");
        let (mut thrifty_design, thrifty_units) = propose(&thrifty).unwrap();
        assert!(assert_units_match(&mut thrifty_design, &thrifty_units) > 0);
        for unit in &thrifty_units {
            assert!(unit.instances.iter().all(|instance| instance.nodes == 1), "{}", unit.name);
            assert_eq!(unit.area_merged, unit.area_identical, "{}", unit.name);
        }
        assert!(instances(&thrifty_units) >= instances(&units));

        // What would change the machine is refused, and says what.
        let err = |text: &str| propose(text).err().unwrap();
        assert!(err("(hw-plan (unit a (members ADD)))").contains("are in no unit"));
        assert!(err("(hw-plan (unit a (members ADD NOPE)))").contains("`NOPE` is not"));
        assert!(err("(hw-plan (unit a (members ADD)) (unit b (members ADD)))").contains("is in `a` and in `b`"));
        assert!(err("(hw-plan (unit a (members ADD MUL)))").contains("one latency"));
        assert!(err("(hw-plan (unit a (sharing sometimes) (members ADD)))").contains("sharing is"));
        assert!(err("(plan)").contains("expected `(hw-plan"));
    }

    #[test]
    fn a_merged_unit_has_no_combinational_loop() {
        // Ascending ids are a topological order, so a node whose argument is
        // not below it would be a cycle. Checked on the merged graph because
        // merging is the only thing that could make one.
        let mut design = design(include_str!("../examples/rv64i.axisl"));
        let (_, units) = build_units(&mut design);
        for unit in &units {
            for id in design.graph.cone(&[unit.root]) {
                assert!(design.graph.node(id).args.iter().all(|arg| *arg < id));
            }
        }
    }

    /// A design of bare expressions, each over the operands it names.
    fn expressions(members: &[(&str, &[(&str, u32)], u32)]) -> HwDesign {
        use crate::hw::{lower_expr, HwDatapath};
        use crate::semantics::parse_formal_semantics;
        let mut graph = HwGraph::default();
        let mut datapaths = Vec::new();
        for (source, operands, width) in members {
            let env: HashMap<String, NodeId> = operands
                .iter()
                .map(|(name, width)| (name.to_string(), graph.input(name, *width)))
                .collect();
            let sem = crate::ir::lower(&parse_formal_semantics(source).unwrap(), *width).unwrap();
            let root = lower_expr(&mut graph, &HashMap::new(), &sem, &env, *width);
            datapaths.push(HwDatapath {
                mnemonic: source.to_string(),
                inputs: operands.iter().map(|(name, width)| (name.to_string(), *width)).collect(),
                output_width: *width,
                root,
                unit: String::new(),
                latency: 1,
            });
        }
        HwDesign { graph, datapaths, behaviors: Vec::new(), cycle: None }
    }

    #[test]
    fn a_narrow_operator_on_a_wide_one_is_right_for_every_input() {
        // ⚠️ EXHAUSTIVE, because the solver cannot be asked. Each rule here --
        // the borrow above a narrow subtract, the fill above a narrow shift,
        // the sign under a flag above a narrow divide, ones below a narrow
        // count -- is an arithmetic fact about two widths, and z3 does not
        // finish a 32-bit divide against a 64-bit one (`hw_prove.py` reports
        // those as not proved). At four bits on eight the whole input space is
        // 256 pairs, and the code that runs is the code that ships.
        const WIDE: &[(&str, u32)] = &[("x", 8), ("y", 8)];
        const NARROW: &[(&str, u32)] = &[("u", 4), ("v", 4)];
        let mut design = expressions(&[
            ("(sdiv i8 x y)", WIDE, 8),
            ("(sub i8 x y)", WIDE, 8),
            ("(ashr i8 x y)", WIDE, 8),
            ("(mulh i8 x y)", WIDE, 8),
            ("(clz i8 x)", WIDE, 8),
            ("(cpop i8 x)", WIDE, 8),
            ("(sdiv i4 u v)", NARROW, 4),
            ("(udiv i4 u v)", NARROW, 4),
            ("(srem i4 u v)", NARROW, 4),
            ("(urem i4 u v)", NARROW, 4),
            ("(add i4 u v)", NARROW, 4),
            ("(sub i4 u v)", NARROW, 4),
            ("(icmp_ult i4 u v)", NARROW, 4),
            ("(icmp_uge i4 u v)", NARROW, 4),
            ("(icmp_slt i4 u v)", NARROW, 4),
            ("(icmp_sge i4 u v)", NARROW, 4),
            ("(lshr i4 u v)", NARROW, 4),
            ("(ashr i4 u v)", NARROW, 4),
            ("(shl i4 u v)", NARROW, 4),
            ("(mul i4 u v)", NARROW, 4),
            ("(mulh i4 u v)", NARROW, 4),
            ("(mulhu i4 u v)", NARROW, 4),
            ("(mulhsu i4 u v)", NARROW, 4),
            ("(clz i4 u)", NARROW, 4),
            ("(ctz i4 u)", NARROW, 4),
            ("(cpop i4 u)", NARROW, 4),
        ]);
        let members: Vec<usize> = (0..design.datapaths.len()).collect();
        let unit = merge_unit_with(&mut design, "all", &members, Sharing::Always);
        // One instance of each class, as wide as its widest user: every narrow
        // operator above is riding a wide one.
        let mut classes: Vec<(&str, u32)> =
            unit.instances.iter().map(|instance| (instance.class, instance.width)).collect();
        classes.sort_unstable();
        assert_eq!(
            classes,
            [("addsub", 8), ("clz", 8), ("cpop", 8), ("divrem", 8), ("mulwide", 8), ("shift", 8)]
        );
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        for (code, datapath) in design.datapaths.iter().enumerate() {
            let own = *datapath.root.as_ref().unwrap();
            // A narrow member is exhausted over its eight bits of input, with
            // noise on the wide ports. A wide one is at its instance's own
            // width, where no rule applies, and is sampled.
            let narrow = datapath.inputs[0].1 == 4;
            for pair in 0..256u128 {
                let mut inputs: HashMap<String, u128> = HashMap::new();
                if narrow {
                    inputs.insert("u".into(), pair & 0xf);
                    inputs.insert("v".into(), pair >> 4);
                    inputs.insert("x".into(), rng.next());
                    inputs.insert("y".into(), rng.next());
                } else {
                    inputs.insert("x".into(), rng.next());
                    inputs.insert("y".into(), rng.next());
                    inputs.insert("u".into(), rng.next());
                    inputs.insert("v".into(), rng.next());
                }
                inputs.insert(SELECT_INPUT.to_string(), code as u128);
                assert_eq!(
                    design.graph.eval(unit.root, &inputs),
                    design.graph.eval(own, &inputs),
                    "{} at {pair:#x}",
                    datapath.mnemonic
                );
            }
        }
    }

    #[test]
    fn rv32_and_zbb_merge_and_agree() {
        for source in [
            include_str!("../examples/rv32i.axisl"),
            include_str!("../examples/zbb_like.axisl"),
        ] {
            let mut design = design(source);
            let (_, units) = build_units(&mut design);
            assert!(!units.is_empty());
            assert!(assert_units_match(&mut design, &units) > 0);
        }
    }

    #[test]
    fn a_share_that_takes_a_unit_past_a_core_s_cycle_is_undone() {
        // RV64I with a core that states the planner's own 45 gate delays and
        // keeps every declared latency but the unrolled divider's, which does
        // not fit three. Sharing one adder among the ALU's thirteen makes its
        // stage 47 gate delays deep; apart, it is 37.
        let base = include_str!("../examples/rv64i.axisl");
        let core = "  (defcore c (kind rvmt) (cycle (gates 45)) (timing (latency (DIV 30) (REM 30))))\n";
        let document =
            parse_document(&format!("{}{core})\n", base.trim_end().strip_suffix(')').unwrap())).unwrap();
        validate_document(&document).unwrap();
        let view = crate::timing::as_seen_by(&document, "c").unwrap();
        let alu = |cycle: Option<f64>| {
            let mut design = lower_document(&view);
            design.cycle = cycle;
            let (_, units) = build_units(&mut design);
            let alu = units.into_iter().find(|unit| unit.name == "alu").unwrap();
            let stage = stage_of(&design.graph, &alu);
            (alu, stage)
        };
        let shares = |unit: &MergedUnit, class: &str| {
            unit.instances.iter().any(|instance| instance.class == class && instance.nodes > 1)
        };
        // The planner's own rule is not a cycle anything was promised.
        let (unit, stage) = alu(None);
        assert!(shares(&unit, "addsub") && stage > 45.0, "{stage}");
        assert!(unit.kept_apart.is_empty());
        // A core's is: the adders go back apart, the unit fits, the shifter
        // -- which does not lengthen it -- stays shared, and the reason is
        // published.
        let (unit, stage) = alu(Some(45.0));
        assert!(!shares(&unit, "addsub") && shares(&unit, "shift"));
        assert!(stage <= 45.0, "{stage}");
        let kept = unit.kept_apart.iter().find(|kept| kept.class == "addsub").unwrap();
        assert_eq!(kept.because, "cycle");
        assert!(kept.stage > 45.0 && kept.saves > 0.0, "{kept:?}");
        // At a cycle it fits, the share stands.
        let (unit, _) = alu(Some(50.0));
        assert!(unit.kept_apart.iter().all(|kept| kept.because != "cycle"));
    }

    #[test]
    fn a_share_is_taken_when_it_keeps_half_of_what_it_removes() {
        let shares = |source: &str| {
            let mut design = design(source);
            let (_, units) = build_units(&mut design);
            let alu = units.into_iter().find(|unit| unit.name == "alu").unwrap();
            let shared: Vec<&str> = alu
                .instances
                .iter()
                .filter(|instance| instance.nodes > 1)
                .map(|instance| instance.class)
                .collect();
            (shared.join(" "), alu)
        };
        // RV32I's ALU: one adder for seven instructions, one shifter for six.
        // Yosys agrees both save area.
        let (shared, alu) = shares(include_str!("../examples/rv32i.axisl"));
        assert_eq!(shared, "addsub shift");
        assert!(alu.kept_apart.is_empty());
        assert!(alu.area_merged < alu.area_identical);

        // zbb_like's: a rotator shared behind bit reversals and a comparator
        // shared behind operand muxes both save by the model -- and cost
        // area synthesised. Each keeps under half of what it removes, and is
        // left apart, by name.
        let (shared, alu) = shares(include_str!("../examples/zbb_like.axisl"));
        assert_eq!(shared, "");
        let apart: Vec<&str> = alu.kept_apart.iter().map(|kept| kept.class).collect();
        assert_eq!(apart, ["addsub", "rotate"]);
        for kept in &alu.kept_apart {
            assert!(kept.saves > 0.0 && kept.saves < SHARING_MARGIN * kept.removes, "{kept:?}");
        }
    }
}
