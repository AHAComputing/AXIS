//! What a core says about time, where it differs from its instructions.
//!
//! An instruction's `(latency N)` and `(unit NAME)` are the reference
//! machine's. A `defcore` may say otherwise (`docs/core_timing_design.md`),
//! and this file is the ONE place the order of precedence exists: everything
//! that asks how long an instruction takes on a core, or which unit runs it,
//! asks here.

use crate::ast::{Core, Document, Instruction};

/// `(timing (latency (MUL 2) ...) (class-latency (alu 1) ...) (unit (MAC mul) ...))`
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoreTiming {
    /// Cycles by mnemonic prefix. The longest prefix an instruction's
    /// mnemonic starts with wins.
    pub latency: Vec<(String, u32)>,
    /// Cycles for every instruction issued to a unit, by the unit's name --
    /// the unit the instruction resolves to ON THIS CORE, so an instruction a
    /// `unit` clause moved takes the latency of where it went.
    pub class_latency: Vec<(String, u32)>,
    /// The unit that runs an instruction on this core, by mnemonic prefix.
    pub unit: Vec<(String, String)>,
    /// Prefixes whose latency is `derived`: each instruction they decide is
    /// given the fewest cycles its netlist needs at the core's cycle.
    pub derived: Vec<String>,
    /// What `derived` came to, per instruction, filled when the document is
    /// read (`resolve_derived`). Not written by hand and not printed.
    pub floors: Vec<(String, u32)>,
    /// The micro-ops an instruction is cracked into on this core, by mnemonic
    /// prefix: `(micro-ops (LDADD (lsu 2) (alu 1)))`, each a unit and the
    /// cycles it takes there, in order. What each one reads, writes and
    /// loads is NOT written: it is derived from the instruction's effects
    /// (`Core::micro_ops_of`).
    pub micro_ops: Vec<(String, Vec<(String, u32)>)>,
    /// The pairs this core's decoder makes one operation of
    /// (docs/rename_design.md, FU1): `(fuse (SLT BNE) (LUI ADDI))`, a head
    /// and the tail that follows it, each by mnemonic prefix. Which pairs is
    /// the core's to say. Whether two WORDS are such a pair is not written:
    /// the tail reads what the head writes and they leave one register
    /// between them, told from the operands they name.
    pub fuse: Vec<(String, String)>,
}

/// One micro-op of an instruction a core cracks (docs/micro_ops_design.md).
///
/// A core says only which unit runs each micro-op and for how long. The rest
/// is the instruction's own account of itself, read off its effects:
///
/// * a micro-op on the instruction's OWN unit does its memory -- the
///   accesses, in the order the instruction makes them, one a micro-op and
///   the last one taking any left over;
/// * a micro-op on another unit computes. A result that reads no load -- an
///   address written back -- is the first such micro-op's, and waits for no
///   load; a result that IS a load is the loading micro-op's own; a result
///   computed from a load is the first computing micro-op after it;
/// * what no operand names -- state, a fixed register, the pc -- is the last
///   micro-op's.
///
/// Every micro-op reads the instruction's operands as they were before the
/// instruction: one that needs another's result says so in `after`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroOp {
    pub unit: String,
    pub latency: u32,
    /// Which of the instruction's memory accesses it makes, counted in the
    /// order the instruction makes them.
    pub accesses: Vec<usize>,
    /// And every access after its last: an instruction may make more than
    /// its effects say (a guard, a kernel), and none goes unowned.
    pub rest: bool,
    /// Operands it reads and operands it writes, by name.
    pub reads: Vec<String>,
    pub writes: Vec<String>,
    /// Whether it takes what no operand names: state read and written, a
    /// fixed register, the pc.
    pub implicit: bool,
    /// The micro-ops whose results it needs, by position.
    pub after: Vec<usize>,
}

/// How strongly `prefix` matches `mnemonic`: its length, or 0 for `*`, which
/// matches everything and loses to anything more specific.
fn matches(prefix: &str, mnemonic: &str) -> Option<usize> {
    if prefix == "*" {
        Some(0)
    } else {
        mnemonic.starts_with(prefix).then_some(prefix.len())
    }
}

/// The entry of `table` with the longest prefix `mnemonic` starts with.
fn longest<'a, T>(table: &'a [(String, T)], mnemonic: &str) -> Option<&'a T> {
    table
        .iter()
        .filter_map(|(prefix, value)| Some((matches(prefix, mnemonic)?, value)))
        .max_by_key(|(strength, _)| *strength)
        .map(|(_, value)| value)
}

/// Whether the latency deciding `mnemonic` is a `derived` one: the most
/// specific prefix naming it, numbered or derived, is a derived prefix.
fn derived_decides(timing: &CoreTiming, mnemonic: &str) -> bool {
    let numbered = timing.latency.iter().filter_map(|(p, _)| matches(p, mnemonic)).max();
    let derived = timing.derived.iter().filter_map(|p| matches(p, mnemonic)).max();
    match (derived, numbered) {
        (Some(d), Some(n)) => d > n,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Fill each `derived` latency with the floor it asks for, on every core
/// that states a cycle. Run when a document is read, so every reader after
/// it sees a number. A core that asks for `derived` without a cycle is left
/// as it is, and refused by validation.
///
/// An instruction a derived prefix decides that has no value netlist -- an
/// effect, or something the netlist lowering declines -- keeps its own
/// latency: there is no floor to give it.
pub fn resolve_derived(document: &mut Document) {
    for index in 0..document.cores.len() {
        let core = &document.cores[index];
        let Some(timing) = &core.timing else { continue };
        if timing.derived.is_empty() || core.cycle_gates == 0 {
            continue;
        }
        let resolved: Vec<(String, u32)> = floors(document, core)
            .into_iter()
            .filter(|floor| !floor.effect && derived_decides(timing, &floor.mnemonic))
            .map(|floor| (floor.mnemonic, floor.needed))
            .collect();
        if let Some(timing) = &mut document.cores[index].timing {
            timing.floors = resolved;
        }
    }
}

impl Core {
    /// Whether this core runs `instruction` at all: it implements the
    /// instruction's ISA, or one of them does not say.
    pub fn decodes(&self, instruction: &Instruction) -> bool {
        self.implements.trim().is_empty()
            || instruction.isa.trim().is_empty()
            || self.implements.eq_ignore_ascii_case(instruction.isa.trim())
    }

    /// The unit NAMED for `instruction` on this core: what the core says,
    /// else what the instruction says. Empty when neither names one.
    pub fn named_unit_of<'a>(&'a self, instruction: &'a Instruction) -> &'a str {
        self.timing
            .as_ref()
            .and_then(|timing| longest(&timing.unit, &instruction.mnemonic))
            .map_or(instruction.unit.trim(), String::as_str)
    }

    /// The unit that runs `instruction` on this core: the one named for it
    /// (`named_unit_of`), else the one its effects derive
    /// (`crate::simt::derived_unit_class`: lsu, fpu or alu) -- the rule a SIMT
    /// core applies, so the two engines charge an instruction that names no
    /// unit to the same kind of unit. Precedence agreed for T1/U4c: the
    /// core's override, then the instruction's own, then derived. A derived
    /// class the core does not declare is no unit, as on a SIMT core.
    pub fn unit_of<'a>(&'a self, instruction: &'a Instruction) -> &'a str {
        let named = self.named_unit_of(instruction);
        if named.is_empty() { crate::simt::derived_unit_class(instruction) } else { named }
    }

    /// The cycles `instruction` takes on this core: the core's word for the
    /// mnemonic, else its word for the unit the instruction runs on here,
    /// else the instruction's own.
    pub fn latency_of(&self, instruction: &Instruction) -> u32 {
        let Some(timing) = &self.timing else {
            return instruction.latency_cycles;
        };
        if let Some((_, cycles)) = timing.floors.iter().find(|(m, _)| *m == instruction.mnemonic) {
            return *cycles;
        }
        if !derived_decides(timing, &instruction.mnemonic) {
            if let Some(cycles) = longest(&timing.latency, &instruction.mnemonic) {
                return *cycles;
            }
        }
        let unit = self.unit_of(instruction);
        timing
            .class_latency
            .iter()
            .find(|(class, _)| class.eq_ignore_ascii_case(unit))
            .map_or(instruction.latency_cycles, |(_, cycles)| *cycles)
    }

    /// The micro-ops `instruction` is cracked into on this core: `None` when
    /// the core does not crack it, and an error -- by name -- when it says to
    /// and the instruction's effects cannot be divided that way.
    pub fn micro_ops_of(&self, instruction: &Instruction) -> Option<Result<Vec<MicroOp>, String>> {
        let declared = self
            .timing
            .as_ref()
            .and_then(|timing| longest(&timing.micro_ops, &instruction.mnemonic))?;
        Some(crack(self, instruction, declared))
    }

    /// Every instruction this core decodes and cracks, with its micro-ops.
    /// One that cannot be cracked as declared is left out: validation has
    /// said so by name.
    pub fn cracked<'a>(&'a self, instructions: &'a [Instruction]) -> Vec<(&'a str, Vec<MicroOp>)> {
        instructions
            .iter()
            .filter(|instruction| self.decodes(instruction))
            .filter_map(|instruction| {
                Some((instruction.mnemonic.as_str(), self.micro_ops_of(instruction)?.ok()?))
            })
            .collect()
    }

    /// Every instruction this core decodes whose unit or latency here is not
    /// its own: `(mnemonic, unit, latency)`.
    pub fn retimed<'a>(&'a self, instructions: &'a [Instruction]) -> Vec<(&'a str, &'a str, u32)> {
        instructions
            .iter()
            .filter(|instruction| self.decodes(instruction))
            .filter(|instruction| {
                // NAMED unit: a derived class is the instruction's own on
                // every core, not a decision this core made.
                self.named_unit_of(instruction) != instruction.unit.trim()
                    || self.latency_of(instruction) != instruction.latency_cycles
            })
            .map(|instruction| {
                (instruction.mnemonic.as_str(), self.unit_of(instruction), self.latency_of(instruction))
            })
            .collect()
    }
}

/// Every load in `expr`, outermost first, as the expression of its address.
fn loads_of<'a>(expr: &'a crate::semantics::SemanticExpr, into: &mut Vec<&'a crate::semantics::SemanticExpr>) {
    use crate::semantics::SemanticExpr;
    let SemanticExpr::List(items) = expr else { return };
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "load" || op == "atomic_load") {
        if let Some(address) = items.last() {
            into.push(address);
            loads_of(address, into);
        }
        return;
    }
    for item in items {
        loads_of(item, into);
    }
}

/// The atoms of `expr` that are not inside a load: what the expression reads
/// of the registers, as distinct from what it reads of memory.
fn atoms_outside_loads(expr: &crate::semantics::SemanticExpr, into: &mut Vec<String>) {
    use crate::semantics::SemanticExpr;
    match expr {
        SemanticExpr::Atom(name) => into.push(name.clone()),
        SemanticExpr::List(items) => {
            if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "load" || op == "atomic_load") {
                return;
            }
            for item in items {
                atoms_outside_loads(item, into);
            }
        }
        _ => {}
    }
}

/// `declared` -- units and cycles -- made into micro-ops by dividing
/// `instruction`'s effects among them. The rule is `MicroOp`'s.
fn crack(core: &Core, instruction: &Instruction, declared: &[(String, u32)]) -> Result<Vec<MicroOp>, String> {
    use crate::effects::Loc;
    let name = &instruction.mnemonic;
    if declared.len() < 2 {
        return Err(format!("`{name}` is cracked into one micro-op, which is the instruction"));
    }
    if !crate::effects::behavior_is_authoritative(instruction) {
        return Err(format!(
            "`{name}` says what it does as a value, and micro-ops are divided by effects: it has none to divide"
        ));
    }
    let behavior = instruction.behavior.as_ref().expect("authoritative");
    let own = core.unit_of(instruction);
    let memory: Vec<usize> =
        (0..declared.len()).filter(|&at| declared[at].0.eq_ignore_ascii_case(own)).collect();
    let computes: Vec<usize> = (0..declared.len()).filter(|at| !memory.contains(at)).collect();
    let mut ops: Vec<MicroOp> = declared
        .iter()
        .map(|(unit, latency)| MicroOp {
            unit: unit.clone(),
            latency: *latency,
            accesses: Vec::new(),
            rest: false,
            reads: Vec::new(),
            writes: Vec::new(),
            implicit: false,
            after: Vec::new(),
        })
        .collect();
    let operand = |atom: &String| instruction.operands.iter().any(|o| &o.name == atom);
    let outside = |expr: &crate::semantics::SemanticExpr| -> Vec<String> {
        let mut atoms = Vec::new();
        atoms_outside_loads(expr, &mut atoms);
        atoms.into_iter().filter(|atom| operand(atom)).collect()
    };
    // Each access, in order, goes to a memory micro-op; and each load is
    // remembered by the address expression it is, so a value that reads it
    // can be told which micro-op made it.
    let mut made = 0usize;
    let mut load_op: Vec<(*const crate::semantics::SemanticExpr, usize)> = Vec::new();
    let mut give = |ops: &mut Vec<MicroOp>, made: &mut usize| -> Result<usize, String> {
        let Some(&last) = memory.last() else {
            return Err(format!(
                "`{name}` touches memory on `{own}`, and none of its micro-ops is on `{own}` to do it"
            ));
        };
        let at = memory.get(*made).copied().unwrap_or(last);
        ops[at].accesses.push(*made);
        *made += 1;
        Ok(at)
    };
    // What each expression of an effect contributes: its loads become
    // accesses, and reading one means waiting for the micro-op that made it.
    let mut loads_in = |ops: &mut Vec<MicroOp>,
                        made: &mut usize,
                        load_op: &mut Vec<(*const crate::semantics::SemanticExpr, usize)>,
                        expr: &crate::semantics::SemanticExpr|
     -> Result<Vec<usize>, String> {
        let mut addresses = Vec::new();
        loads_of(expr, &mut addresses);
        let mut makers = Vec::new();
        for address in addresses {
            let at = give(ops, made)?;
            for atom in outside(address) {
                ops[at].reads.push(atom);
            }
            load_op.push((address as *const _, at));
            makers.push(at);
        }
        Ok(makers)
    };
    let last = declared.len() - 1;
    // Whether the instruction does anything no operand names: that is the
    // last micro-op's, and is work.
    let mut unnamed = false;
    for effect in &behavior.effects {
        let mut makers = loads_in(&mut ops, &mut made, &mut load_op, &effect.value.expr)?;
        if let Some(guard) = &effect.guard {
            makers.extend(loads_in(&mut ops, &mut made, &mut load_op, &guard.expr)?);
        }
        let mut reads = outside(&effect.value.expr);
        if let Some(guard) = &effect.guard {
            reads.extend(outside(&guard.expr));
        }
        let at = match &effect.loc {
            Loc::Mem { addr, .. } | Loc::Port { port: addr, .. } => {
                makers.extend(loads_in(&mut ops, &mut made, &mut load_op, &addr.expr)?);
                reads.extend(outside(&addr.expr));
                give(&mut ops, &mut made)?
            }
            Loc::Reg(register) => {
                let pure = reads.is_empty() && makers.len() == 1;
                let at = if makers.is_empty() {
                    computes.first().copied().unwrap_or(0)
                } else if pure {
                    makers[0]
                } else {
                    let latest = makers.iter().copied().max().unwrap_or(0);
                    match computes.iter().copied().find(|&at| at > latest) {
                        Some(at) => at,
                        None => {
                            return Err(format!(
                                "`{name}` computes `{register}` from what it loads, and no micro-op after the load is on a unit other than `{own}` to compute it"
                            ));
                        }
                    }
                };
                ops[at].writes.push(register.clone());
                at
            }
            Loc::Barrier { .. } => give(&mut ops, &mut made)?,
            Loc::FixedReg { .. } | Loc::State { .. } | Loc::Pc | Loc::Trap => {
                unnamed = true;
                last
            }
        };
        ops[at].reads.extend(reads);
        for maker in makers {
            if maker > at {
                return Err(format!(
                    "`{name}`: micro-op {} needs what micro-op {} loads, which comes after it",
                    at + 1,
                    maker + 1
                ));
            }
            if maker != at {
                ops[at].after.push(maker);
            }
        }
    }
    if made == 0 {
        return Err(format!(
            "`{name}` touches no memory, so nothing in it tells one micro-op's work from another's"
        ));
    }
    if memory.len() > made {
        return Err(format!(
            "`{name}` makes {made} memory access(es) and has {} micro-ops on `{own}`: one has nothing to do",
            memory.len()
        ));
    }
    // State an instruction READS belongs with what it writes there.
    ops[last].implicit = true;
    if let Some(&at) = memory.last() {
        ops[at].rest = true;
    }
    for (at, op) in ops.iter_mut().enumerate() {
        for list in [&mut op.reads, &mut op.writes] {
            let mut seen: Vec<String> = Vec::new();
            list.retain(|item| if seen.contains(item) { false } else { seen.push(item.clone()); true });
        }
        op.after.sort_unstable();
        op.after.dedup();
        if op.accesses.is_empty() && op.writes.is_empty() && !(at == last && unnamed) {
            return Err(format!(
                "`{name}`: micro-op {} on `{}` has nothing to do -- no access is its, and no result",
                at + 1,
                op.unit
            ));
        }
    }
    Ok(ops)
}

/// The description as one core sees it: the instructions that core decodes,
/// each with the latency and unit it has THERE, and that core alone.
///
/// Everything that reads an instruction's latency or unit -- the hardware
/// planner, `emit-json`, a simulator -- reads the core's by being given this
/// instead of the description. The core in the view says nothing further
/// about timing: its word is already in the instructions.
pub fn as_seen_by(document: &Document, name: &str) -> Result<Document, String> {
    let core = document
        .cores
        .iter()
        .find(|core| core.name.eq_ignore_ascii_case(name))
        .ok_or_else(|| {
            let known: Vec<&str> = document.cores.iter().map(|core| core.name.as_str()).collect();
            format!("no core `{name}`; the description declares {}", if known.is_empty() {
                "none".to_string()
            } else {
                known.join(", ")
            })
        })?;
    let mut view = document.clone();
    view.instructions.retain(|instruction| core.decodes(instruction));
    for instruction in &mut view.instructions {
        // NAMED unit, not the derived one: a derived class written into the
        // view would tag every instruction, and the hardware planner switches
        // from derived to declared grouping when every built instruction
        // names a unit (agreed with T3). A reader of the view derives it again.
        let (unit, latency) = (core.named_unit_of(instruction).to_string(), core.latency_of(instruction));
        instruction.unit = unit;
        instruction.latency_cycles = latency;
    }
    let mut seen = core.clone();
    seen.timing = None;
    view.cores = vec![seen];
    Ok(view)
}

/// An instruction's netlist against the cycles a core gives it.
#[derive(Debug, Clone, PartialEq)]
pub struct Floor {
    pub mnemonic: String,
    /// The netlist's depth, in gate delays.
    pub depth: f64,
    /// The fewest cycles that depth fits in at the core's cycle.
    pub needed: u32,
    /// The cycles the core gives it.
    pub latency: u32,
    /// Built as an effect -- a branch, a load, a store -- whose netlist is the
    /// address, the condition and the value around the access, and not the
    /// access itself. A floor all the same: the instruction cannot take fewer
    /// cycles than its own arithmetic does. Not what `derived` gives it,
    /// because the memory it waits for is not in the netlist.
    pub effect: bool,
}

/// Every instruction `core` decodes that has a netlist, with the fewest
/// cycles its depth needs at the core's cycle. Empty for a core that states
/// no cycle. An instruction with no netlist has no floor and is not here.
pub fn floors(document: &Document, core: &Core) -> Vec<Floor> {
    if core.cycle_gates == 0 {
        return Vec::new();
    }
    let Ok(view) = as_seen_by(document, &core.name) else { return Vec::new() };
    let design = crate::hw::lower_document(&view);
    let cycle = f64::from(core.cycle_gates);
    let needed = |depth: f64| ((depth / cycle).ceil() as u32).max(1);
    let mut found: Vec<Floor> = design
        .datapaths
        .iter()
        .filter_map(|datapath| {
            let root = *datapath.root.as_ref().ok()?;
            let (_, depth) = design.graph.cone_cost(&[root]);
            Some(Floor {
                mnemonic: datapath.mnemonic.clone(),
                depth,
                needed: needed(depth),
                latency: datapath.latency,
                effect: false,
            })
        })
        .collect();
    for behavior in &design.behaviors {
        let Ok(effects) = &behavior.effects else { continue };
        if found.iter().any(|floor| floor.mnemonic == behavior.mnemonic) {
            continue;
        }
        let Some(instruction) = view.instructions.iter().find(|i| i.mnemonic == behavior.mnemonic) else {
            continue;
        };
        let mut roots: Vec<crate::hw::NodeId> = effects
            .iter()
            .flat_map(|effect| [Some(effect.value), effect.guard, effect.addr])
            .flatten()
            .collect();
        roots.extend(behavior.load.iter().chain(&behavior.extra_loads).map(|load| load.addr));
        let (_, depth) = design.graph.cone_cost(&roots);
        found.push(Floor {
            mnemonic: behavior.mnemonic.clone(),
            depth,
            needed: needed(depth),
            latency: instruction.latency_cycles,
            effect: true,
        });
    }
    found
}

/// Whether what a core says about time is something a machine could mean.
///
/// Every entry has to reach an instruction the core decodes -- an override of
/// nothing is a typo that would otherwise read as a decision -- and a unit a
/// core sends an instruction to has to be one the core has.
pub fn validate(core: &Core, document: &Document) -> Result<(), String> {
    let refuse = |message: String| Err(format!("core `{}` timing: {message}", core.name));
    if core.simt.is_some() && (core.timing.is_some() || core.cycle_gates != 0) {
        return refuse("a simt core states its latencies in `(simt ...)`, and one core has one place for them".to_string());
    }
    validate_clause(core, document)?;
    // ⚠️ The check a declared latency never had. A core that states its
    // cycle is claiming a machine, and AXIS has the netlist: an instruction
    // given fewer cycles than its own circuit needs is a machine that cannot
    // be built from this description, whichever of the two numbers is wrong.
    for floor in floors(document, core) {
        if floor.latency < floor.needed {
            return refuse(format!(
                "`{}` is given {} cycle(s), and its netlist is {:.0} gate delays deep: {} at a cycle of {}",
                floor.mnemonic, floor.latency, floor.depth, floor.needed, core.cycle_gates
            ));
        }
    }
    Ok(())
}

fn validate_clause(core: &Core, document: &Document) -> Result<(), String> {
    let Some(timing) = &core.timing else { return Ok(()) };
    let refuse = |message: String| Err(format!("core `{}` timing: {message}", core.name));
    // A core timed by a model AXIS did not build hands that model its own
    // record of the machine, which carries no retiming. The model would time
    // the instructions' numbers and report them as this core's.
    if !core.model.trim().is_empty() {
        return refuse(format!(
            "it is timed by the external model `{}`, which does not read a core's timing",
            core.model
        ));
    }
    let decoded: Vec<&Instruction> =
        document.instructions.iter().filter(|instruction| core.decodes(instruction)).collect();
    let reaches = |prefix: &str| prefix == "*" || decoded.iter().any(|i| i.mnemonic.starts_with(prefix));
    let twice = |keys: Vec<&String>| -> Option<String> {
        let mut seen = std::collections::HashSet::new();
        keys.into_iter().find(|key| !seen.insert(key.to_ascii_lowercase())).cloned()
    };
    for (prefix, cycles) in &timing.latency {
        if *cycles == 0 {
            return refuse(format!("latency 0 for `{prefix}`: a result is never ready the cycle it issues"));
        }
        if !reaches(prefix) {
            return refuse(format!("latency for `{prefix}`, which names no instruction this core decodes"));
        }
    }
    for prefix in &timing.derived {
        if prefix != "*" && !reaches(prefix) {
            return refuse(format!("latency for `{prefix}`, which names no instruction this core decodes"));
        }
        if core.cycle_gates == 0 {
            return refuse(format!(
                "`{prefix}` asks for a derived latency, which is a number of this core's cycles, \
                 and the core states no `(cycle (gates N))`"
            ));
        }
    }
    for (prefix, unit) in &timing.unit {
        if !reaches(prefix) {
            return refuse(format!("unit for `{prefix}`, which names no instruction this core decodes"));
        }
        if !core.units.iter().any(|declared| declared.name.eq_ignore_ascii_case(unit)) {
            return refuse(format!("`{prefix}` is sent to `{unit}`, a unit this core does not declare"));
        }
    }
    for (class, cycles) in &timing.class_latency {
        if *cycles == 0 {
            return refuse(format!("latency 0 for unit `{class}`: a result is never ready the cycle it issues"));
        }
        if !decoded.iter().any(|instruction| core.unit_of(instruction).eq_ignore_ascii_case(class)) {
            return refuse(format!("latency for unit `{class}`, which no instruction this core decodes issues to"));
        }
    }
    for (prefix, ops) in &timing.micro_ops {
        if ops.len() > 8 {
            return refuse(format!("`{prefix}` is cracked into {} micro-ops; the window holds 8 of one instruction", ops.len()));
        }
        if !reaches(prefix) {
            return refuse(format!("micro-ops for `{prefix}`, which names no instruction this core decodes"));
        }
        for (unit, cycles) in ops {
            if *cycles == 0 {
                return refuse(format!(
                    "a micro-op of `{prefix}` takes 0 cycles on `{unit}`: a result is never ready the cycle it issues"
                ));
            }
            if !core.units.iter().any(|declared| declared.name.eq_ignore_ascii_case(unit)) {
                return refuse(format!("a micro-op of `{prefix}` is on `{unit}`, a unit this core does not declare"));
            }
        }
    }
    for instruction in &decoded {
        if let Some(Err(why)) = core.micro_ops_of(instruction) {
            return refuse(why);
        }
    }
    // FU1: a pair is two instructions this core decodes whole, in a window,
    // neither of them one this model cannot make half of an operation.
    for (head, tail) in &timing.fuse {
        if core.rob == 0 || core.simt.is_some() {
            return refuse(format!("`(fuse ({head} {tail}))` with no window of this library's to put the pair in"));
        }
        for (prefix, first) in [(head, true), (tail, false)] {
            if !reaches(prefix) {
                return refuse(format!("fuse `{prefix}`, which names no instruction this core decodes"));
            }
            for instruction in decoded.iter().filter(|i| prefix == "*" || i.mnemonic.starts_with(prefix.as_str())) {
                let why = if core.micro_ops_of(instruction).is_some() {
                    Some("this core cracks")
                } else {
                    fuse_refusal(instruction, first)
                };
                if let Some(why) = why {
                    return refuse(format!(
                        "fuse `({head} {tail})` reaches `{}`, which {why}",
                        instruction.mnemonic
                    ));
                }
            }
        }
    }
    {
        let mut seen = std::collections::HashSet::new();
        if let Some((head, tail)) = timing.fuse.iter().find(|pair| !seen.insert((pair.0.as_str(), pair.1.as_str()))) {
            return refuse(format!("`({head} {tail})` is fused twice"));
        }
    }
    for (what, keys) in [
        ("micro-ops", timing.micro_ops.iter().map(|(key, _)| key).collect::<Vec<_>>()),
        ("latency", timing.latency.iter().map(|(key, _)| key).chain(timing.derived.iter()).collect::<Vec<_>>()),
        ("class-latency", timing.class_latency.iter().map(|(key, _)| key).collect()),
        ("unit", timing.unit.iter().map(|(key, _)| key).collect()),
    ] {
        if let Some(key) = twice(keys) {
            return refuse(format!("`{key}` is given a {what} twice"));
        }
    }
    Ok(())
}

/// Whether an ISA's `(memory-model ...)` lets stores to different addresses
/// reach memory out of program order, and loads be satisfied out of order
/// (docs/memory_model_design.md).
pub fn memory_model_is_relaxed(model: &str) -> bool {
    matches!(model.to_ascii_lowercase().as_str(), "rvwmo" | "armv8" | "weak")
}

/// Whether `instruction` ORDERS MEMORY (docs/memory_model_design.md, WM1): it
/// may not retire past stores this core has not yet written, and what it
/// stores is written when it retires. A barrier that orders memory; an access
/// that is atomic -- a store-conditional is one -- or acquires or releases;
/// and an instruction that both reads and writes memory. Told from the
/// instruction's effects.
pub fn orders_memory(instruction: &Instruction) -> bool {
    use crate::effects::{Loc, MemoryOrder};
    let Some(behavior) = instruction.behavior.as_ref() else { return false };
    let (loads, stores) = crate::simt::memory_ops(instruction);
    if loads && stores {
        return true;
    }
    behavior.effects.iter().any(|effect| {
        effect.value.load_atomic
            || effect.value.load_order != MemoryOrder::Relaxed
            || match &effect.loc {
                Loc::Barrier { kind, .. } => crate::effects::barrier_kind(kind).is_some_and(|k| k.orders_memory),
                Loc::Mem { order, atomic, .. } => *atomic || *order != MemoryOrder::Relaxed,
                _ => false,
            }
    })
}

/// The ways `instruction` is a ZERO IDIOM (docs/rename_design.md, ZI1): pairs
/// of operands that, naming one register, make its result nothing whatever
/// that register holds -- a register xor-ed with itself, or subtracted from
/// itself. Told from what the instruction computes, as a move is.
pub fn zero_forms(instruction: &Instruction) -> Vec<(String, String)> {
    use crate::semantics::SemanticExpr;
    let outputs: Vec<&crate::ast::Operand> = instruction.operands.iter().filter(|o| o.output).collect();
    let [out] = outputs.as_slice() else { return Vec::new() };
    if out.input || !crate::ast::is_register_kind(&out.kind) {
        return Vec::new();
    }
    let Ok(SemanticExpr::List(items)) = crate::effects::pure_value_semantics(instruction) else { return Vec::new() };
    let [SemanticExpr::Atom(head), SemanticExpr::Atom(_), SemanticExpr::Atom(a), SemanticExpr::Atom(b)] =
        items.as_slice()
    else {
        return Vec::new();
    };
    // Two operands of one kind and width: one register when they name one.
    let register = |name: &str| {
        instruction
            .operands
            .iter()
            .find(|o| o.name == name && o.input && !o.output && !o.element && crate::ast::is_register_kind(&o.kind))
    };
    match (matches!(head.as_str(), "xor" | "sub"), register(a), register(b)) {
        (true, Some(x), Some(y)) if a != b && x.kind == y.kind && x.width == y.width => {
            vec![(a.clone(), b.clone())]
        }
        _ => Vec::new(),
    }
}

/// Why `instruction` cannot be half of a fused pair (docs/rename_design.md,
/// FU1) -- the first half, or the second -- or `None`. Told from its effects.
pub fn fuse_refusal(instruction: &Instruction, head: bool) -> Option<&'static str> {
    let (loads, stores) = crate::simt::memory_ops(instruction);
    // FU2: the second half may be a load -- an address formed into the access.
    if stores || (head && loads) {
        return Some("touches memory; a pair's second half may read it, and nothing else of a pair may");
    }
    if loads && orders_memory(instruction) {
        return Some("orders memory; a load that does is not half of a pair");
    }
    let jumps = instruction
        .behavior
        .as_ref()
        .is_some_and(|b| b.effects.iter().any(|e| matches!(e.loc, crate::effects::Loc::Pc)));
    if head && jumps {
        return Some("changes the pc; what is decoded after it is not what runs after it");
    }
    None
}

/// The ways `instruction` is a register MOVE (docs/rename_design.md, ME1):
/// `(source, zero)` pairs, each naming the operand whose value the result is
/// and, when the instruction is a move only for some words, the operand that
/// must then be nothing -- the zero register, or an immediate of zero.
///
/// Told from what the instruction computes and from nothing else: its one
/// result is its one output register, and the value is an input register of
/// the same kind and width, or that register added to, or-ed, xor-ed with or
/// shifted by another operand, or with another subtracted from it. An
/// instruction that says what it does any other way -- effects beside the
/// result, a routine, a guard -- is not one.
pub fn move_forms(instruction: &Instruction) -> Vec<(String, Option<String>)> {
    use crate::semantics::SemanticExpr;
    let outputs: Vec<&crate::ast::Operand> = instruction.operands.iter().filter(|o| o.output).collect();
    let [out] = outputs.as_slice() else { return Vec::new() };
    if out.input || !crate::ast::is_register_kind(&out.kind) {
        return Vec::new();
    }
    let Ok(value) = crate::effects::pure_value_semantics(instruction) else { return Vec::new() };
    let input = |name: &str| instruction.operands.iter().find(|o| o.name == name && o.input && !o.output);
    let source = |name: &str| input(name).filter(|o| o.kind == out.kind && o.width == out.width && !o.element);
    match &value {
        SemanticExpr::Atom(name) => source(name).map(|o| vec![(o.name.clone(), None)]).unwrap_or_default(),
        SemanticExpr::List(items) => {
            let [SemanticExpr::Atom(head), SemanticExpr::Atom(ty), SemanticExpr::Atom(a), SemanticExpr::Atom(b)] =
                items.as_slice()
            else {
                return Vec::new();
            };
            // The value is as wide as the register: nothing is cut off or filled in.
            if ty.trim_start_matches(|c: char| c.is_ascii_alphabetic()).parse::<u32>().ok() != Some(out.width) {
                return Vec::new();
            }
            let either = matches!(head.as_str(), "add" | "or" | "xor");
            let second = matches!(head.as_str(), "sub" | "shl" | "lshr" | "ashr");
            if !either && !second {
                return Vec::new();
            }
            let mut forms = Vec::new();
            // `a` is the source when `b` is nothing; and for the three that
            // commute, the other way round.
            if let (Some(src), Some(zero)) = (source(a), input(b)) {
                if a != b {
                    forms.push((src.name.clone(), Some(zero.name.clone())));
                }
            }
            if either {
                if let (Some(src), Some(zero)) = (source(b), input(a)) {
                    if a != b {
                        forms.push((src.name.clone(), Some(zero.name.clone())));
                    }
                }
            }
            forms
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::lisp::parse_document as parse_module;
    use crate::validate::validate_document;

    const BASE: &str = include_str!("../examples/issue_width.axisl");

    /// `issue_width.axisl` with one more core, given this `(timing ...)`.
    fn with_core(timing: &str) -> String {
        let core = format!(
            "  (defcore retimed (kind rvmt) (implements iw32) (issue-width 2)\n    \
             (units (alu (count 2) (pipelined true)) (mul (count 1) (pipelined true))\n           \
             (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true)))\n    {timing})\n"
        );
        format!("{}{core})\n", BASE.trim_end().strip_suffix(')').unwrap())
    }

    fn refused(timing: &str) -> String {
        let document = parse_module(&with_core(timing)).expect("parses");
        validate_document(&document).expect_err("is refused").to_string()
    }

    #[test]
    fn micro_ops_are_divided_by_the_instructions_effects() {
        let document = parse_module(&with_core(
            "(timing (micro-ops (IWLA (lsu 2) (alu 1)) (IWLP (lsu 2) (alu 1))))",
        ))
        .unwrap();
        validate_document(&document).unwrap();
        let core = document.cores.iter().find(|core| core.name == "retimed").unwrap();
        let plan = |mnemonic: &str| {
            let instruction = document.instructions.iter().find(|i| i.mnemonic == mnemonic).unwrap();
            core.micro_ops_of(instruction).unwrap().unwrap()
        };
        let names = |list: &[String]| list.join(" ");
        // A load added to a register: the load reads the address; the add
        // reads the addend, writes the sum, and waits for the load.
        let add = plan("IWLA");
        assert_eq!((add[0].accesses.as_slice(), names(&add[0].reads), names(&add[0].writes)), (&[0usize][..], "rs1".to_string(), String::new()));
        assert_eq!((names(&add[1].reads), names(&add[1].writes), add[1].after.as_slice()), ("rs2".to_string(), "rd".to_string(), &[0usize][..]));
        // A load that moves its base on: the base is the add's, and waits
        // for no load.
        let post = plan("IWLP");
        assert_eq!((names(&post[0].writes), names(&post[1].writes)), ("rd".to_string(), "rs1".to_string()));
        assert!(post[1].after.is_empty() && post[1].accesses.is_empty());
        // An instruction the core does not crack has no plan, and the text
        // survives a round trip.
        let plain = document.instructions.iter().find(|i| i.mnemonic == "IWLW").unwrap();
        assert!(core.micro_ops_of(plain).is_none());
        let again = parse_module(&crate::emit_lisp(&document)).unwrap();
        assert_eq!(again.cores.iter().find(|c| c.name == "retimed").unwrap().timing, core.timing);
        for (clause, why) in [
            ("(IWLA (alu 1) (lsu 2))", "computes `rd` from what it loads"),
            ("(IWLA (lsu 2))", "one micro-op"),
            ("(IWLA (lsu 2) (lsu 1))", "computes `rd` from what it loads"),
            ("(IWADD (alu 1) (alu 1))", "as a value"),
            ("(IWLA (lsu 2) (fpu 1))", "does not declare"),
            ("(IWLA (lsu 0) (alu 1))", "0 cycles"),
            ("(IWLW (lsu 1) (alu 1))", "has nothing to do"),
            ("(NOPE (lsu 1) (alu 1))", "names no instruction"),
        ] {
            let said = refused(&format!("(timing (micro-ops {clause}))"));
            assert!(said.contains(why), "{clause}: {said}");
        }
    }

    #[test]
    fn a_core_that_says_nothing_is_its_instructions() {
        let document = parse_module(BASE).unwrap();
        for core in document.cores.iter().filter(|core| core.timing.is_none()) {
            assert!(core.retimed(&document.instructions).is_empty(), "{}", core.name);
            for instruction in &document.instructions {
                assert_eq!(core.latency_of(instruction), instruction.latency_cycles);
                assert_eq!(core.named_unit_of(instruction), instruction.unit.trim());
                let derived = if instruction.unit.trim().is_empty() {
                    crate::simt::derived_unit_class(instruction)
                } else {
                    instruction.unit.trim()
                };
                assert_eq!(core.unit_of(instruction), derived);
            }
        }
    }

    #[test]
    fn the_core_decides_and_the_longest_prefix_wins() {
        let document = parse_module(BASE).unwrap();
        let by_unit = |unit: &str| -> Vec<String> {
            document.instructions.iter().filter(|i| i.unit == unit).map(|i| i.mnemonic.clone()).collect()
        };
        let (br, mul) = (by_unit("br"), by_unit("mul"));
        assert!(br.len() >= 3 && !mul.is_empty(), "the corpus this test reads has changed");
        // One branch by its whole name, the class for the rest, and another
        // branch moved onto the multiplier.
        let timing = format!(
            "(timing (latency ({} 7)) (class-latency (br 2) (mul 5)) (unit ({} mul)))",
            br[0], br[1]
        );
        let document = parse_module(&with_core(&timing)).unwrap();
        validate_document(&document).unwrap();
        let core = document.cores.iter().find(|core| core.name == "retimed").unwrap();
        let of = |mnemonic: &str| {
            let instruction = document.instructions.iter().find(|i| i.mnemonic == mnemonic).unwrap();
            (core.unit_of(instruction).to_string(), core.latency_of(instruction))
        };
        // Its own name beats its class.
        assert_eq!(of(&br[0]), ("br".to_string(), 7));
        // Moved, it takes the latency of where it went, not where it was.
        assert_eq!(of(&br[1]), ("mul".to_string(), 5));
        assert_eq!(of(&mul[0]), ("mul".to_string(), 5));
        for other in &br[2..] {
            assert_eq!(of(other), ("br".to_string(), 2));
        }
        // Exactly those are reported as retimed, and nothing else.
        assert_eq!(core.retimed(&document.instructions).len(), br.len() + mul.len());
        // And the cores that said nothing still say nothing.
        for other in document.cores.iter().filter(|core| core.name != "retimed") {
            assert!(other.retimed(&document.instructions).is_empty());
        }
    }

    #[test]
    fn what_it_says_goes_out_and_comes_back() {
        let document = parse_module(BASE).unwrap();
        let alu = document.instructions.iter().find(|i| i.unit == "alu").unwrap().mnemonic.clone();
        let source = with_core(&format!("(timing (latency ({alu} 3)) (class-latency (mul 4)) (unit ({alu} mul)))"));
        let first = parse_module(&source).unwrap();
        let again = parse_module(&crate::emit::emit_lisp(&first)).unwrap();
        let timing = |document: &crate::ast::Document| {
            document.cores.iter().find(|core| core.name == "retimed").unwrap().timing.clone()
        };
        assert!(timing(&first).is_some());
        assert_eq!(timing(&first), timing(&again));
    }

    #[test]
    fn a_core_is_refused_a_latency_its_netlist_does_not_fit() {
        // RV64I says nothing about cores. Given one, with the cycle the
        // hardware planner assumes when nobody says: the multiplier's three
        // declared cycles are more than its netlist needs, and the unrolled
        // divider's three are a tenth of what it needs.
        let base = include_str!("../examples/rv64i.axisl");
        let with = |clauses: &str| {
            let core = format!("  (defcore c (kind rvmt) (implements rv64i) {clauses})\n");
            parse_module(&format!("{}{core})\n", base.trim_end().strip_suffix(')').unwrap())).unwrap()
        };
        // No cycle, no claim: every description before this one.
        validate_document(&with("")).unwrap();
        let said = validate_document(&with("(cycle (gates 45))")).unwrap_err().to_string();
        assert!(said.contains("core `c` timing") && said.contains("at a cycle of 45"), "{said}");
        assert!(said.contains("`DIV") || said.contains("`REM"), "{said}");

        // The core's own word is what is checked, and what satisfies it.
        let slow = "(cycle (gates 45)) (timing (latency (DIV 30) (REM 30)))";
        let document = with(slow);
        validate_document(&document).unwrap();
        let core = document.cores.iter().find(|core| core.name == "c").unwrap();
        let floors = super::floors(&document, core);
        let of = |mnemonic: &str| floors.iter().find(|floor| floor.mnemonic == mnemonic).unwrap();
        assert_eq!((of("MUL").needed, of("MUL").latency), (2, 3));
        assert_eq!((of("DIV").needed, of("DIV").latency), (30, 30));
        assert_eq!(of("ADD").needed, 1);
        // Branches, jumps, loads and stores are floored too, by their own
        // arithmetic: a conditional branch compares and adds a target.
        let branch = of("BEQ");
        assert!(branch.effect && branch.needed >= 1 && branch.latency >= branch.needed);
        assert!(floors.iter().filter(|floor| floor.effect).count() >= 20);
        // And one cycle short is one cycle short.
        let short = "(cycle (gates 45)) (timing (latency (DIV 30) (REM 30) (MUL 1)))";
        assert!(validate_document(&with(short)).unwrap_err().to_string().contains("`MUL"));
        // A longer cycle needs fewer of them.
        let long = with("(cycle (gates 90)) (timing (latency (DIV 15) (REM 15) (MUL 1)))");
        validate_document(&long).unwrap();
    }

    #[test]
    fn a_derived_latency_is_the_floor_and_a_named_one_still_wins() {
        let base = include_str!("../examples/rv64i.axisl");
        let with = |clauses: &str| {
            let core = format!("  (defcore c (kind rvmt) (implements rv64i) {clauses})\n");
            parse_module(&format!("{}{core})\n", base.trim_end().strip_suffix(')').unwrap())).unwrap()
        };
        let latency = |document: &crate::ast::Document, mnemonic: &str| {
            let core = document.cores.iter().find(|core| core.name == "c").unwrap();
            let instruction = document.instructions.iter().find(|i| i.mnemonic == mnemonic).unwrap();
            core.latency_of(instruction)
        };
        // Every instruction at its floor: the machine the netlists ARE.
        let built = with("(cycle (gates 45)) (timing (latency (* derived)))");
        validate_document(&built).unwrap();
        // A load keeps what it declares: its floor is its address, and the
        // memory it waits for is not in the netlist.
        let load = built.instructions.iter().find(|i| i.mnemonic == "LD").unwrap();
        assert_eq!(latency(&built, "LD"), load.latency_cycles);
        assert_eq!(
            (latency(&built, "ADD"), latency(&built, "MUL"), latency(&built, "DIV")),
            (1, 2, 30)
        );
        // A prefix that names it beats `*`; `*` beats nothing named.
        let mixed = with("(cycle (gates 45)) (timing (latency (* derived) (MUL 3)))");
        validate_document(&mixed).unwrap();
        assert_eq!((latency(&mixed, "MUL"), latency(&mixed, "DIV")), (3, 30));
        // And a derived prefix more specific than a numbered one beats it.
        let narrow = with("(cycle (gates 45)) (timing (latency (D 40) (DIVU derived) (REM 40)))");
        validate_document(&narrow).unwrap();
        assert_eq!((latency(&narrow, "DIV"), latency(&narrow, "DIVU")), (40, 30));
        // Derived needs a cycle to be a number of.
        let refused = validate_document(&with("(timing (latency (* derived)))")).unwrap_err().to_string();
        assert!(refused.contains("states no `(cycle"), "{refused}");
        // It prints as asked, not as resolved, and resolves again on reading.
        let again = parse_module(&crate::emit::emit_lisp(&built)).unwrap();
        assert!(crate::emit::emit_lisp(&built).contains("(* derived)"));
        assert_eq!(latency(&again, "DIV"), 30);
    }

    #[test]
    fn a_view_is_the_description_with_the_core_s_numbers_in_it() {
        let document = parse_module(BASE).unwrap();
        let br: Vec<String> =
            document.instructions.iter().filter(|i| i.unit == "br").map(|i| i.mnemonic.clone()).collect();
        let source = with_core(&format!("(timing (latency ({} 7)) (unit ({} mul)))", br[0], br[1]));
        let document = parse_module(&source).unwrap();
        let view = super::as_seen_by(&document, "retimed").unwrap();
        let of = |mnemonic: &str| view.instructions.iter().find(|i| i.mnemonic == mnemonic).unwrap();
        assert_eq!(of(&br[0]).latency_cycles, 7);
        assert_eq!(of(&br[1]).unit, "mul");
        // One core, which has nothing left to say: reading the view through
        // it again changes nothing.
        assert_eq!(view.cores.len(), 1);
        assert!(view.cores[0].retimed(&view.instructions).is_empty());
        assert!(super::as_seen_by(&document, "nobody").unwrap_err().contains("no core `nobody`"));
    }

    #[test]
    fn an_override_of_nothing_is_refused() {
        assert!(refused("(timing (latency (NOPE 2)))").contains("names no instruction"));
        assert!(refused("(timing (class-latency (fpu 2)))").contains("no instruction this core decodes issues to"));
        let document = parse_module(BASE).unwrap();
        let alu = document.instructions.iter().find(|i| i.unit == "alu").unwrap().mnemonic.clone();
        assert!(refused(&format!("(timing (latency ({alu} 0)))")).contains("latency 0"));
        assert!(refused(&format!("(timing (unit ({alu} fpu)))")).contains("does not declare"));
        assert!(refused(&format!("(timing (latency ({alu} 2) ({alu} 3)))")).contains("twice"));
        // A core an external model times hands that model a record with no
        // retiming in it: the model would time the instructions' numbers.
        assert!(refused(&format!("(model vendor_x) (timing (latency ({alu} 2)))")).contains("external model"));
    }
}
