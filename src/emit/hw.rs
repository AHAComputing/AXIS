//! The hardware backends over [`crate::hw`]: structural PyRTL, and the plan
//! that says what was built and why.
//!
//! `emit-pyrtl` ships the semantics as strings and an interpreter that turns
//! them into a circuit when Python runs. `emit-hw-pyrtl` ships the circuit:
//! straight-line PyRTL, one statement per node of a netlist AXIS already
//! analysed -- so the area and depth in `emit-hw-json` are of the very nodes
//! the Python builds, and a merged functional unit can exist at all.

use std::collections::{BTreeMap, HashMap};

use super::common::{json_string, python_ident};
use super::semantics::{emit_smt2, smt_ident_of};
use crate::ast::Document;
use crate::hw::{
    ceil_log2, lower_document, mask, operator_costs, EffectKind, HwDesign, HwGraph, HwOp, NodeId,
    COST_REFERENCE, LOAD_INPUT, PS_PER_GATE, SELECT_INPUT,
};
use crate::hw_units::{
    build_units_with, cycle_budget, merge_slot_unit, parse_plan, plan_slot_units, render_plan,
    schedule, schedule_roots, MemberRef, MergedUnit, Schedule, SlotSource, SlotUnit, UnitClass,
};

/// The helpers the emitted statements call. Each is one primitive of
/// [`HwOp`], written to the definition in `hw::eval_op`.
const PYRTL_PRELUDE: &str = r#"def _fit(value, width):
    value = pyrtl.as_wires(value)
    if len(value) > width:
        return value[:width]
    if len(value) < width:
        return value.zero_extended(width)
    return value

def _repeat(bit, count):
    return bit if count == 1 else bit.sign_extended(count)

def _addsub(a, b, sub, n):
    # a + (sub ? ~b : b) + sub, n + 1 bits: the top one is the carry out.
    b = b ^ _repeat(sub, n)
    return _fit(a.zero_extended(n + 1) + b.zero_extended(n + 1) + sub, n + 1)

def _reg(value):
    value = pyrtl.as_wires(value)
    register = pyrtl.Register(len(value))
    register.next <<= value
    return register

def _delay(value, cycles):
    for _ in range(cycles):
        value = _reg(value)
    return value

def _mul(a, b, width, cuts=0):
    # With cuts, the multiplier is taken a slice of `b` at a time, the running
    # sum and what is still to be multiplied registered between slices.
    if cuts == 0:
        return _fit(a * b, width)
    step = -(-len(b) // (cuts + 1))
    chunks = [b[lo:min(lo + step, len(b))] for lo in range(0, len(b), step)]
    total = pyrtl.Const(0, bitwidth=width)
    for index in range(len(chunks)):
        partial = a * chunks[index]
        if index:
            partial = pyrtl.concat(partial, pyrtl.Const(0, bitwidth=index * step))
        total = _fit(total + partial, width)
        if index + 1 < len(chunks):
            total, a = _reg(total), _reg(a)
            chunks = chunks[:index + 1] + [_reg(rest) for rest in chunks[index + 1:]]
    return _delay(total, cuts - (len(chunks) - 1))

def _mulwide(a, b, sa, sb, n, cuts=0):
    a = pyrtl.concat(_repeat(sa & a[n - 1], n), a)
    b = pyrtl.concat(_repeat(sb & b[n - 1], n), b)
    return _mul(a, b, 2 * n, cuts)

def _divrem(a, b, signed, n, cuts=0):
    # Restoring division on magnitudes, the signs put back after. Truncates
    # toward zero; the remainder takes the dividend's sign; a zero divisor
    # gives zero for both. With cuts, everything still needed is registered
    # after each even share of the quotient bits.
    a_neg = signed & a[n - 1]
    b_neg = signed & b[n - 1]
    a_mag = pyrtl.select(a_neg, _fit(~a + 1, n), a)
    b_mag = pyrtl.select(b_neg, _fit(~b + 1, n), b)
    divisor = b_mag.zero_extended(n + 1)
    by_zero = b == 0
    remainder = pyrtl.Const(0, bitwidth=n + 1)
    quotient, made = None, 0
    share = -(-n // (cuts + 1))
    for index, bit in enumerate(range(n - 1, -1, -1)):
        shifted = pyrtl.concat(remainder[:n], a_mag[bit])
        take = shifted >= divisor
        remainder = pyrtl.select(take, _fit(shifted - divisor, n + 1), shifted)
        quotient = take if quotient is None else pyrtl.concat(quotient, take)
        if (index + 1) % share == 0 and index + 1 < n and made < cuts:
            remainder, quotient, a_mag, divisor, a_neg, b_neg, by_zero = (
                _reg(wire) for wire in (remainder, quotient, a_mag, divisor, a_neg, b_neg, by_zero))
            made += 1
    remainder = remainder[:n]
    quotient = pyrtl.select(a_neg ^ b_neg, _fit(~quotient + 1, n), quotient)
    remainder = pyrtl.select(a_neg, _fit(~remainder + 1, n), remainder)
    out = pyrtl.select(by_zero, pyrtl.Const(0, bitwidth=2 * n),
                       pyrtl.concat(remainder, quotient))
    return _delay(out, cuts - made)

def _shr(a, amount, fill, n):
    # A mux row per amount bit that can matter; any bit above them shifts
    # everything out.
    filled = _repeat(fill, n)
    value, over = a, None
    for bit in range(len(amount)):
        step = 1 << bit
        if step < n:
            value = pyrtl.select(amount[bit], pyrtl.concat(filled[:step], value[step:]), value)
        else:
            over = amount[bit] if over is None else over | amount[bit]
    return value if over is None else pyrtl.select(over, filled, value)

def _ror(a, amount, n):
    value = a
    for bit in range(len(amount)):
        step = (1 << bit) % n
        if step:
            value = pyrtl.select(amount[bit], pyrtl.concat(value[:step], value[step:]), value)
    return value

def _clz(a, n, width):
    # The highest set bit decides, so it is applied last.
    count = pyrtl.Const(n, bitwidth=width)
    for bit in range(n):
        count = pyrtl.select(a[bit], pyrtl.Const(n - 1 - bit, bitwidth=width), count)
    return count

def _cpop(a, n, width):
    terms = [a[bit] for bit in range(n)]
    while len(terms) > 1:
        terms = [terms[i] + terms[i + 1] if i + 1 < len(terms) else terms[i]
                 for i in range(0, len(terms), 2)]
    return _fit(terms[0], width)

"#;

/// Python names for a builder's parameters: the operand names, kept apart from
/// each other and from the names the module itself uses.
fn parameter_names(inputs: &[(String, u32)]) -> Vec<String> {
    let mut taken: Vec<String> = vec!["sel".to_string(), "pyrtl".to_string()];
    let mut names = Vec::new();
    for (name, _) in inputs {
        let mut ident = python_ident(name);
        // `python_ident` cannot produce a name starting with `n` and a digit
        // from an operand that does not, but an operand may be called `n3`.
        while taken.contains(&ident)
            || PYTHON_KEYWORDS.contains(&ident.as_str())
            || (ident.starts_with('n') && ident[1..].chars().all(|ch| ch.is_ascii_digit()))
        {
            ident.push('_');
        }
        taken.push(ident.clone());
        names.push(ident);
    }
    names
}

const PYTHON_KEYWORDS: &[&str] = &[
    "and", "as", "assert", "async", "await", "break", "class", "continue", "def", "del", "elif",
    "else", "except", "finally", "for", "from", "global", "if", "import", "in", "is", "lambda",
    "nonlocal", "not", "or", "pass", "raise", "return", "try", "while", "with", "yield",
];

/// One statement per node of `root`'s cone, in dependency order.
///
/// With a schedule, the same statements over delayed arguments: each argument
/// is read through as many registers as lie between the stage it is ready in
/// and the stage its reader works in, and a multiplier or divider that spans
/// stages is given the registers inside it. The result is `valid` and the root,
/// both `registers` cycles after the inputs.
fn emit_cone(out: &mut String, graph: &HwGraph, root: NodeId, parameters: &HashMap<String, String>,
             schedule: Option<&Schedule>) {
    emit_cones(out, graph, &[root], parameters, schedule, None);
}

/// The same for several roots at once, returning `returns` -- an expression
/// over their names -- where one root's value is not the whole answer.
fn emit_cones(out: &mut String, graph: &HwGraph, roots: &[NodeId],
              parameters: &HashMap<String, String>, schedule: Option<&Schedule>,
              returns: Option<&str>) {
    let root = roots[0];
    let mut delayed: std::collections::HashSet<(NodeId, u32)> = std::collections::HashSet::new();
    // The name of `id`'s value `cycles` registers later, defining it if this
    // is its first reader there.
    let mut later = |out: &mut String, id: NodeId, cycles: u32| -> String {
        for step in 1..=cycles {
            if delayed.insert((id, step)) {
                let from = if step == 1 { format!("n{id}") } else { format!("n{id}_d{}", step - 1) };
                out.push_str(&format!("    n{id}_d{step} = _reg({from})\n"));
            }
        }
        if cycles == 0 { format!("n{id}") } else { format!("n{id}_d{cycles}") }
    };
    for id in graph.cone(roots) {
        let node = graph.node(id);
        let names: Vec<String> = node
            .args
            .iter()
            .map(|arg| match schedule {
                Some(plan) if graph.node(*arg).op != HwOp::Const => {
                    later(out, *arg, plan.input_stage(id) - plan.stage[arg])
                }
                _ => format!("n{arg}"),
            })
            .collect();
        let arg = |index: usize| names[index].clone();
        let cuts = schedule.and_then(|plan| plan.cuts.get(&id).copied()).unwrap_or(0);
        let width = node.width;
        let data = |index: usize| graph.width(node.args[index]);
        let expr = match node.op {
            HwOp::Input => format!("_fit({}, {width})", parameters[&node.name]),
            HwOp::Const => format!("pyrtl.Const({}, bitwidth={width})", node.value),
            HwOp::AddSub => format!("_addsub({}, {}, {}, {})", arg(0), arg(1), arg(2), data(0)),
            HwOp::Mul => format!("_mul({}, {}, {width}, {cuts})", arg(0), arg(1)),
            HwOp::MulWide => format!(
                "_mulwide({}, {}, {}, {}, {}, {cuts})",
                arg(0),
                arg(1),
                arg(2),
                arg(3),
                data(0)
            ),
            HwOp::DivRem => {
                format!("_divrem({}, {}, {}, {}, {cuts})", arg(0), arg(1), arg(2), data(0))
            }
            HwOp::Shr => format!("_shr({}, {}, {}, {width})", arg(0), arg(1), arg(2)),
            HwOp::Ror => format!("_ror({}, {}, {width})", arg(0), arg(1)),
            HwOp::Clz => format!("_clz({}, {}, {width})", arg(0), data(0)),
            HwOp::Cpop => format!("_cpop({}, {}, {width})", arg(0), data(0)),
            HwOp::Eq => format!("{} == {}", arg(0), arg(1)),
            HwOp::And => format!("{} & {}", arg(0), arg(1)),
            HwOp::Or => format!("{} | {}", arg(0), arg(1)),
            HwOp::Xor => format!("{} ^ {}", arg(0), arg(1)),
            HwOp::Not => format!("~{}", arg(0)),
            HwOp::Mux => format!("pyrtl.select({}, {}, {})", arg(0), arg(1), arg(2)),
            HwOp::Zext => format!("{}.zero_extended({width})", arg(0)),
            HwOp::Sext => format!("{}.sign_extended({width})", arg(0)),
            HwOp::Slice => {
                let lo = node.value as u32;
                format!("{}[{lo}:{}]", arg(0), lo + width)
            }
            HwOp::Concat => format!("pyrtl.concat({}, {})", arg(0), arg(1)),
            HwOp::Rev => format!("{}[::-1]", arg(0)),
        };
        out.push_str(&format!("    n{id} = {expr}\n"));
    }
    if let Some(returns) = returns {
        // `@i` in `returns` is root `i` as it leaves: after the registers
        // left on its path, where there is a schedule.
        let mut text = returns.to_string();
        let mut leaving = Vec::new();
        for (index, root) in roots.iter().enumerate() {
            let name = match schedule {
                Some(plan) if graph.node(*root).op != HwOp::Const => {
                    later(out, *root, plan.registers - plan.stage[root])
                }
                _ => format!("n{root}"),
            };
            leaving.push((format!("@{index}"), name));
        }
        // Longest placeholder first, so `@1` does not eat the front of `@12`.
        leaving.sort_by_key(|(placeholder, _)| std::cmp::Reverse(placeholder.len()));
        for (placeholder, name) in leaving {
            text = text.replace(&placeholder, &name);
        }
        match schedule {
            Some(plan) => out.push_str(&format!(
                "    return _delay(valid, {}), {text}\n\n",
                plan.registers
            )),
            None => out.push_str(&format!("    return {text}\n\n")),
        }
        return;
    }
    match schedule {
        None => out.push_str(&format!("    return n{root}\n\n")),
        Some(plan) => {
            let result = if graph.node(root).op == HwOp::Const {
                format!("n{root}")
            } else {
                later(out, root, plan.registers - plan.stage[&root])
            };
            out.push_str(&format!(
                "    return _delay(valid, {}), {result}\n\n",
                plan.registers
            ));
        }
    }
}

fn python_inputs(inputs: &[(String, u32)]) -> String {
    let items: Vec<String> = inputs
        .iter()
        .map(|(name, width)| format!("({}, {width})", json_string(name)))
        .collect();
    format!("[{}]", items.join(", "))
}

/// The builder names, one per datapath with a circuit, made distinct. Two
/// mnemonics that differ only in punctuation would otherwise define one
/// Python function twice and silently keep the second.
fn builder_names(design: &HwDesign) -> Vec<String> {
    let mut seen: HashMap<String, u32> = HashMap::new();
    design
        .datapaths
        .iter()
        .map(|datapath| {
            let base = format!("build_{}", python_ident(&datapath.mnemonic));
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            if *count == 1 {
                base
            } else {
                format!("{base}__{count}")
            }
        })
        .collect()
}

/// The units of a document: AXIS's own plan, or the one in `plan`.
fn planned(document: &Document, plan: Option<&str>, cycle: Option<f64>)
           -> Result<(HwDesign, &'static str, Vec<MergedUnit>), String> {
    let mut design = lower_document(document);
    design.cycle = cycle;
    let proposed = plan.map(parse_plan).transpose()?;
    let (grouping, units) = build_units_with(&mut design, proposed.as_deref())?;
    Ok((design, grouping, units))
}

/// The plan AXIS would build, in the form `--hw-plan` reads: where a proposer
/// starts from.
pub fn emit_hw_plan(document: &Document) -> String {
    emit_hw_plan_at(document, None)
}

/// The same, at a core's cycle. With `cycle` the document is one core's view
/// of the description (`timing::as_seen_by`): its latencies and units are
/// that core's, and what fits a cycle is decided at its cycle.
pub fn emit_hw_plan_at(document: &Document, cycle: Option<f64>) -> String {
    let (design, _, units) = planned(document, None, cycle).expect("AXIS's own plan is valid");
    render_plan(&design, &units)
}

pub fn emit_hw_pyrtl(document: &Document) -> String {
    emit_hw_pyrtl_planned(document, None).expect("AXIS's own plan is valid")
}

pub fn emit_hw_pyrtl_planned(document: &Document, plan: Option<&str>) -> Result<String, String> {
    emit_hw_pyrtl_at(document, plan, None)
}

pub fn emit_hw_pyrtl_at(document: &Document, plan: Option<&str>, cycle: Option<f64>)
    -> Result<String, String> {
    let (design, grouping, units) = planned(document, plan, cycle)?;
    let builders = builder_names(&design);
    let mut out = String::new();
    out.push_str(
        "# Generated by AXIS. Structural PyRTL: a netlist per instruction, and the\n\
         # functional units those netlists merge into.\n",
    );
    out.push_str("# Importing aha activates PCE's PyRTL fork when this file is used inside PCE.\n");
    out.push_str("try:\n    import aha  # type: ignore  # noqa: F401\nexcept Exception:\n    pass\n\n");
    out.push_str("import pyrtl\n\n");
    out.push_str("AXIS_SCHEMA = \"axis.hw-pyrtl.v1\"\n\n");
    out.push_str(PYRTL_PRELUDE);

    out.push_str("INSTRUCTIONS = {\n");
    for (datapath, builder) in design.datapaths.iter().zip(&builders) {
        if datapath.root.is_err() {
            continue;
        }
        out.push_str(&format!(
            "    {}: {{\"builder\": {}, \"inputs\": {}, \"output_width\": {}}},\n",
            json_string(&datapath.mnemonic),
            json_string(builder),
            python_inputs(&datapath.inputs),
            datapath.output_width
        ));
    }
    out.push_str("}\n\n");
    // ⚠️ Named, with the reason. An instruction with no circuit is not an
    // instruction with a wrong one, and a consumer that could not tell would
    // have to treat a generator that builds less as one that still works.
    out.push_str("DECLINED = {\n");
    for datapath in &design.datapaths {
        if let Err(reason) = &datapath.root {
            out.push_str(&format!(
                "    {}: {},\n",
                json_string(&datapath.mnemonic),
                json_string(reason)
            ));
        }
    }
    out.push_str("}\n\n");
    out.push_str("UNITS = {\n");
    for unit in &units {
        let members: Vec<String> = unit
            .members
            .iter()
            .map(|member| json_string(&design.datapaths[*member].mnemonic))
            .collect();
        out.push_str(&format!(
            "    {}: {{\"builder\": {}, \"grouping\": {}, \"members\": [{}], \
             \"select_width\": {}, \"inputs\": {}, \"output_width\": {}, \"latency\": {}, \
             \"pipelined_builder\": {}}},\n",
            json_string(&unit.name),
            json_string(&format!("build_unit_{}", python_ident(&unit.name))),
            json_string(grouping),
            members.join(", "),
            unit.select_width,
            python_inputs(&unit.inputs),
            unit.output_width,
            unit.latency,
            json_string(&format!("build_unit_{}_pipelined", python_ident(&unit.name)))
        ));
    }
    out.push_str("}\n\n");

    for (datapath, builder) in design.datapaths.iter().zip(&builders) {
        let Ok(root) = &datapath.root else { continue };
        let names = parameter_names(&datapath.inputs);
        let parameters: HashMap<String, String> = datapath
            .inputs
            .iter()
            .map(|(name, _)| name.clone())
            .zip(names.iter().cloned())
            .collect();
        out.push_str(&format!("def {builder}({}):\n", names.join(", ")));
        emit_cone(&mut out, &design.graph, *root, &parameters, None);
    }
    for unit in &units {
        let names = parameter_names(&unit.inputs);
        let mut parameters: HashMap<String, String> = unit
            .inputs
            .iter()
            .map(|(name, _)| name.clone())
            .zip(names.iter().cloned())
            .collect();
        parameters.insert(SELECT_INPUT.to_string(), "sel".to_string());
        // A member's position in `members` is the code that selects it. A unit
        // of one instruction has nothing to select and takes no `sel`.
        let mut signature = names.clone();
        if unit.select_width > 0 {
            signature.insert(0, "sel".to_string());
        }
        out.push_str(&format!(
            "def build_unit_{}({}):\n",
            python_ident(&unit.name),
            signature.join(", ")
        ));
        emit_cone(&mut out, &design.graph, unit.root, &parameters, None);
        // The same unit in time: as many registers as its instructions take
        // cycles beyond the first, a new instruction accepted every cycle.
        signature.insert(0, "valid".to_string());
        out.push_str(&format!(
            "def build_unit_{}_pipelined({}):\n",
            python_ident(&unit.name),
            signature.join(", ")
        ));
        let plan = schedule(&design.graph, unit.root, unit.latency - 1);
        emit_cone(&mut out, &design.graph, unit.root, &parameters, Some(&plan));
    }
    emit_effects(&mut out, &design);
    out.push_str(EXTENSION_BRIDGE);
    Ok(out)
}

/// The instructions stated as effects: for each, what it writes, and a builder
/// that returns the wire for every value, guard and address.
///
/// These are not merged into units. A branch's comparison, its target and a
/// load's address are live in the same cycle of one instruction, and which of
/// them share an adder with which other instruction's is a question about a
/// core's stages that a unit plan does not ask yet.
fn emit_effects(out: &mut String, design: &HwDesign) {
    let python = |flag: bool| if flag { "True" } else { "False" };
    out.push_str("EFFECTS = {\n");
    for behavior in &design.behaviors {
        let Ok(effects) = &behavior.effects else { continue };
        let listed: Vec<String> = effects
            .iter()
            .map(|effect| {
                let (kind, dest) = match &effect.kind {
                    EffectKind::Set { dest } => ("set", json_string(dest)),
                    EffectKind::SetPc => ("setpc", "None".to_string()),
                    EffectKind::SetState { name } => ("setstate", json_string(name)),
                    EffectKind::Store => ("store", "None".to_string()),
                };
                format!(
                    "{{\"kind\": \"{kind}\", \"dest\": {dest}, \"width\": {}, \"guarded\": {}}}",
                    effect.width,
                    python(effect.guard.is_some())
                )
            })
            .collect();
        let describe = |load: &crate::hw::HwLoad| {
            format!(
                "{{\"width\": {}, \"signed\": {}, \"address_width\": {}, \"guarded\": {}}}",
                load.width,
                python(load.signed),
                design.graph.width(load.addr),
                python(load.guard.is_some())
            )
        };
        let load = behavior.load.as_ref().map(describe).unwrap_or_else(|| "None".to_string());
        // Every load, the first included, in the order they are made: a later
        // one's address may read what an earlier one returned.
        let all_loads: Vec<String> =
            behavior.load.iter().chain(&behavior.extra_loads).map(describe).collect();
        out.push_str(&format!(
            "    {}: {{\"builder\": {}, \"inputs\": {}, \"state\": [{}], \"load\": {load}, \
             \"loads\": [{}], \"effects\": [{}]}},\n",
            json_string(&behavior.mnemonic),
            json_string(&format!("build_effect_{}", python_ident(&behavior.mnemonic))),
            python_inputs(&behavior.inputs),
            behavior.state_inputs.iter().map(|name| json_string(name)).collect::<Vec<_>>().join(", "),
            all_loads.join(", "),
            listed.join(", ")
        ));
    }
    out.push_str("}\n\n");
    out.push_str("EFFECTS_DECLINED = {\n");
    for behavior in &design.behaviors {
        if let Err(reason) = &behavior.effects {
            out.push_str(&format!(
                "    {}: {},\n",
                json_string(&behavior.mnemonic),
                json_string(reason)
            ));
        }
    }
    out.push_str("}\n\n");
    for behavior in &design.behaviors {
        let Ok(effects) = &behavior.effects else { continue };
        let names = parameter_names(&behavior.inputs);
        let mut parameters: HashMap<String, String> = behavior
            .inputs
            .iter()
            .map(|(name, _)| name.clone())
            .zip(names.iter().cloned())
            .collect();
        let mut signature = names.clone();
        // What the load read comes in last, and only where there is a load.
        if behavior.load.is_some() {
            parameters.insert(LOAD_INPUT.to_string(), "load".to_string());
            signature.push("load".to_string());
        }
        // Further loads' values after it: `load1`, `load2`, ...
        for (k, load) in behavior.extra_loads.iter().enumerate() {
            let parameter = format!("load{}", k + 1);
            parameters.insert(load.input.clone(), parameter.clone());
            signature.push(parameter);
        }
        let mut roots = Vec::new();
        let name = |id: Option<NodeId>, roots: &mut Vec<NodeId>| match id {
            Some(id) => {
                roots.push(id);
                format!("n{id}")
            }
            None => "None".to_string(),
        };
        let load_addr = name(behavior.load.as_ref().map(|load| load.addr), &mut roots);
        let load_addrs: Vec<String> = behavior
            .load
            .iter()
            .chain(&behavior.extra_loads)
            .map(|load| name(Some(load.addr), &mut roots))
            .collect();
        // When each load is made: `None` always, else a one-bit wire.
        let load_guards: Vec<String> = behavior
            .load
            .iter()
            .chain(&behavior.extra_loads)
            .map(|load| name(load.guard, &mut roots))
            .collect();
        let wires: Vec<String> = effects
            .iter()
            .map(|effect| {
                format!(
                    "{{\"value\": {}, \"guard\": {}, \"addr\": {}}}",
                    name(Some(effect.value), &mut roots),
                    name(effect.guard, &mut roots),
                    name(effect.addr, &mut roots)
                )
            })
            .collect();
        out.push_str(&format!(
            "def build_effect_{}({}):\n",
            python_ident(&behavior.mnemonic),
            signature.join(", ")
        ));
        let returns =
            format!(
                "{{\"load_addr\": {load_addr}, \"load_addrs\": [{}], \"load_guards\": [{}], \"effects\": [{}]}}",
                load_addrs.join(", "),
                load_guards.join(", "),
                wires.join(", ")
            );
        emit_cones(out, &design.graph, &roots, &parameters, None, Some(&returns));
    }
}

/// The seam an existing core's custom-instruction slot plugs into.
///
/// PCE's `ExtensionRegistry.register_from_adl` takes a map from mnemonic to a
/// callable that builds the result wire, and says of it that "ADL alone cannot
/// supply the hardware semantics callable ... the integrator provides the
/// callables". This is that map, made of the netlists above.
const EXTENSION_BRIDGE: &str = r#"def extension_semantics(xlen):
    """Mnemonic -> callable(*srcs) returning the xlen-wide result wire.

    The sources are an instruction's input operands in declaration order; a
    caller may pass more than an instruction reads. An instruction whose
    operands or result do not fit in xlen bits is left out rather than
    truncated: a core that could not hold its result cannot run it.
    """
    def bind(builder, arity):
        def semantics(*srcs):
            if len(srcs) < arity:
                raise ValueError(f"{builder.__name__} reads {arity} operands, given {len(srcs)}")
            return _fit(builder(*srcs[:arity]), xlen)
        return semantics

    table = {}
    for mnemonic, entry in INSTRUCTIONS.items():
        widths = [width for _, width in entry["inputs"]] + [entry["output_width"]]
        if max(widths) <= xlen:
            table[mnemonic] = bind(globals()[entry["builder"]], len(entry["inputs"]))
    return table

def extension_datapath(xlen, mnemonics, second_operand=None):
    """ONE datapath for the named instructions: the merged units, not a
    circuit each.

    Returns callable(matches, src0, src1, immediate) -> the xlen-wide result,
    where `matches` are one-bit wires, one per mnemonic and in that order, of
    which at most one is set. An instruction's first operand is `src0`; its
    second is `src1`, or `immediate` where `second_operand[mnemonic]` says
    "immediate". A core's dispatch already has those match wires, so the
    units' select costs it nothing to produce.
    """
    second_operand = second_operand or {}
    eligible = extension_semantics(xlen)
    for mnemonic in mnemonics:
        if mnemonic not in eligible:
            raise ValueError(f"{mnemonic} has no netlist that fits in {xlen} bits")
        if len(INSTRUCTIONS[mnemonic]["inputs"]) > 2:
            raise ValueError(f"{mnemonic} reads more than two operands")

    def any_of(wires):
        while len(wires) > 1:
            wires = [wires[i] | wires[i + 1] if i + 1 < len(wires) else wires[i]
                     for i in range(0, len(wires), 2)]
        return wires[0]

    def one_of(groups, width):
        # The wire whose enable is set; the enables exclude each other.
        if len(groups) == 1:
            return _fit(groups[0][0], width)
        return any_of([_fit(wire, width) & _repeat(enable, width) for wire, enable in groups])

    def datapath(matches, src0, src1, immediate):
        match = dict(zip(mnemonics, matches))
        results = []
        for unit in UNITS.values():
            members = [(code, m) for code, m in enumerate(unit["members"]) if m in match]
            if not members:
                continue
            ports = []
            for port, width in unit["inputs"]:
                groups = {}
                for _, mnemonic in members:
                    names = [name for name, _ in INSTRUCTIONS[mnemonic]["inputs"]]
                    if port not in names:
                        continue
                    wire = src0 if names.index(port) == 0 else (
                        immediate if second_operand.get(mnemonic) == "immediate" else src1)
                    groups.setdefault(id(wire), (wire, []))[1].append(match[mnemonic])
                ports.append(one_of([(wire, any_of(enables)) for wire, enables in groups.values()],
                                    width) if groups else pyrtl.Const(0, bitwidth=width))
            if unit["select_width"]:
                width = unit["select_width"]
                ports.insert(0, one_of([(pyrtl.Const(code, bitwidth=width), match[m])
                                        for code, m in members], width))
            running = any_of([match[m] for _, m in members])
            results.append((globals()[unit["builder"]](*ports), running))
        if len(results) == 1:
            return _fit(results[0][0], xlen)
        return one_of(results, xlen)

    return datapath
"#;

/// How many of each shareable operator a cone holds.
fn operator_census(graph: &HwGraph, root: NodeId) -> BTreeMap<&'static str, usize> {
    let mut census = BTreeMap::new();
    for id in graph.cone(&[root]) {
        if let Some(class) = UnitClass::of(graph.node(id).op) {
            *census.entry(class.name()).or_insert(0) += 1;
        }
    }
    census
}

fn json_inputs(inputs: &[(String, u32)]) -> String {
    let items: Vec<String> = inputs
        .iter()
        .map(|(name, width)| format!("[{}, {width}]", json_string(name)))
        .collect();
    format!("[{}]", items.join(", "))
}

fn unit_json(design: &HwDesign, unit: &MergedUnit, grouping: &str, budget: f64) -> String {
    let plan = schedule(&design.graph, unit.root, unit.latency - 1);
    let mnemonic = |member: &usize| json_string(&design.datapaths[*member].mnemonic);
    let members: Vec<String> = unit.members.iter().map(mnemonic).collect();
    let instances: Vec<String> = unit
        .instances
        .iter()
        .map(|instance| {
            let users: Vec<String> = instance
                .members
                .iter()
                .map(|code| mnemonic(&unit.members[*code]))
                .collect();
            format!(
                "        {{\"class\": {}, \"width\": {}, \"nodes\": {}, \"members\": [{}]}}",
                json_string(instance.class),
                instance.width,
                instance.nodes,
                users.join(", ")
            )
        })
        .collect();
    format!(
        "    {{\n      \"name\": {},\n      \"grouping\": {},\n      \"members\": [{}],\n      \
         \"select_width\": {},\n      \"inputs\": {},\n      \"output_width\": {},\n      \
         \"area\": {{\"separate\": {:.1}, \"identical_shared\": {:.1}, \"merged\": {:.1}}},\n      \
         \"area_by_operator\": {{{}}},\n      \
         \"kept_apart\": [{}],\n      \
         \"depth\": {{\"slowest_member\": {:.1}, \"merged\": {:.1}}},\n      \
         \"timing\": {{\"latency\": {}, \"registers\": {}, \"stage_delay\": {:.1}, \
         \"cycles_at_budget\": {}}},\n      \
         \"instances\": [\n{}\n      ]\n    }}",
        json_string(&unit.name),
        json_string(grouping),
        members.join(", "),
        unit.select_width,
        json_inputs(&unit.inputs),
        unit.output_width,
        unit.area_separate,
        unit.area_identical,
        unit.area_merged,
        unit.area_by_operator
            .iter()
            .map(|(operator, area)| format!("\"{operator}\": {area:.1}"))
            .collect::<Vec<_>>()
            .join(", "),
        unit.kept_apart
            .iter()
            .map(|kept| format!(
                "{{\"class\": \"{}\", \"because\": \"{}\", \"removes\": {:.1}, \"saves\": {:.1}, \"stage\": {:.1}}}",
                kept.class, kept.because, kept.removes, kept.saves, kept.stage
            ))
            .collect::<Vec<_>>()
            .join(", "),
        unit.depth_slowest_member,
        unit.depth_merged,
        unit.latency,
        plan.registers,
        plan.stage_delay,
        // The cycles the unit would need for every stage to fit the budget:
        // what the description's latency is measured against.
        (unit.depth_merged / budget).ceil().max(1.0) as u32,
        instances.join(",\n")
    )
}

/// What was built: every instruction's size or the reason it has none, and
/// every unit's members, operators and what merging saved.
pub fn emit_hw_json(document: &Document) -> String {
    emit_hw_json_planned(document, None).expect("AXIS's own plan is valid")
}

pub fn emit_hw_json_planned(document: &Document, plan: Option<&str>) -> Result<String, String> {
    emit_hw_json_at(document, plan, None)
}

pub fn emit_hw_json_at(document: &Document, plan: Option<&str>, cycle: Option<f64>)
    -> Result<String, String> {
    let (design, grouping, units) = planned(document, plan, cycle)?;
    let budget = cycle_budget(&design);
    let mut instructions = Vec::new();
    for datapath in &design.datapaths {
        let head = format!(
            "    {{\"mnemonic\": {}, \"inputs\": {}, \"output_width\": {}",
            json_string(&datapath.mnemonic),
            json_inputs(&datapath.inputs),
            datapath.output_width
        );
        instructions.push(match &datapath.root {
            Ok(root) => {
                let (area, depth) = design.graph.cone_cost(&[*root]);
                let census: Vec<String> = operator_census(&design.graph, *root)
                    .into_iter()
                    .map(|(class, count)| format!("{}: {count}", json_string(class)))
                    .collect();
                // The cycles the description (or the core whose view this
                // is) gives it, beside the fewest its depth fits in.
                format!(
                    "{head}, \"status\": \"built\", \"area\": {area:.1}, \"depth\": {depth:.1}, \
                     \"latency\": {}, \"cycles_needed\": {}, \"operators\": {{{}}}}}",
                    datapath.latency,
                    (depth / budget).ceil().max(1.0) as u32,
                    census.join(", ")
                )
            }
            Err(reason) => format!(
                "{head}, \"status\": \"declined\", \"reason\": {}}}",
                json_string(reason)
            ),
        });
    }
    let units: Vec<String> = units.iter().map(|unit| unit_json(&design, unit, grouping, budget)).collect();
    let behaviors: Vec<String> = design
        .behaviors
        .iter()
        .map(|behavior| match &behavior.effects {
            Ok(effects) => {
                let mut roots: Vec<NodeId> = effects
                    .iter()
                    .flat_map(|effect| [Some(effect.value), effect.guard, effect.addr])
                    .flatten()
                    .collect();
                roots.extend(behavior.load.iter().chain(&behavior.extra_loads).map(|load| load.addr));
                let (area, depth) = design.graph.cone_cost(&roots);
                format!(
                    "    {{\"mnemonic\": {}, \"status\": \"built\", \"effects\": {}, \
                     \"area\": {area:.1}, \"depth\": {depth:.1}}}",
                    json_string(&behavior.mnemonic),
                    effects.len()
                )
            }
            Err(reason) => format!(
                "    {{\"mnemonic\": {}, \"status\": \"declined\", \"reason\": {}}}",
                json_string(&behavior.mnemonic),
                json_string(reason)
            ),
        })
        .collect();
    Ok(format!(
        "{{\n  \"schema\": \"axis.hw-plan.v1\",\n  \"cost_model\": {{\"area_unit\": \
         \"nand2-equivalent\", \"delay_unit\": \"gate\", \"calibrated\": true, \
         \"reference\": {}, \"ps_per_gate\": {PS_PER_GATE:.1}, \
         \"cycle_budget\": {budget:.1}, \"operators\": [\n{}\n  ]}},\n  \"instructions\": [\n{}\n  ],\n  \"units\": [\n{}\n  ],\n  \
         \"effects\": [\n{}\n  ]\n}}\n",
        json_string(COST_REFERENCE),
        operator_costs()
            .iter()
            .map(|(name, width, area, delay)| format!(
                "    {{\"operator\": \"{name}\", \"width\": {width}, \"area\": {area:.1}, \"delay\": {delay:.1}}}"
            ))
            .collect::<Vec<_>>()
            .join(",\n"),
        instructions.join(",\n"),
        units.join(",\n"),
        behaviors.join(",\n")
    ))
}

/// One node as an SMT-LIB bit-vector term over its arguments' names. The same
/// definitions as `hw::eval_op` and the PyRTL prelude, a third time -- which is
/// the point: the proof is of the netlist against `emit-smt2`'s statement of
/// the instruction, and that statement was written without knowing the netlist
/// exists.
fn smt_node(graph: &HwGraph, id: NodeId, parameters: &HashMap<String, (String, u32)>) -> String {
    let node = graph.node(id);
    let arg = |index: usize| format!("n{}", node.args[index]);
    let width = node.width;
    let data = |index: usize| graph.width(node.args[index]);
    let bit = |value: &str| format!("(= {value} #b1)");
    let literal = |value: u128, width: u32| format!("(_ bv{value} {width})");
    match node.op {
        HwOp::Input => {
            let (name, declared) = &parameters[&node.name];
            if *declared == width {
                name.clone()
            } else {
                format!("((_ extract {} 0) {name})", width - 1)
            }
        }
        HwOp::Const => literal(node.value, width),
        HwOp::AddSub => {
            let n = data(0);
            format!(
                "(bvadd ((_ zero_extend 1) {a}) ((_ zero_extend 1) (ite {sub} (bvnot {b}) {b})) \
                 ((_ zero_extend {n}) {s}))",
                a = arg(0),
                b = arg(1),
                s = arg(2),
                sub = bit(&arg(2))
            )
        }
        HwOp::Mul => format!("(bvmul {} {})", arg(0), arg(1)),
        HwOp::MulWide => {
            let n = data(0);
            let read = |value: String, signed: String| {
                format!(
                    "(concat ((_ repeat {n}) (bvand {signed} ((_ extract {top} {top}) {value}))) {value})",
                    top = n - 1
                )
            };
            format!("(bvmul {} {})", read(arg(0), arg(2)), read(arg(1), arg(3)))
        }
        HwOp::DivRem => {
            let n = data(0);
            format!(
                "(ite (= {b} {zero}) {none} (ite {signed} (concat (bvsrem {a} {b}) (bvsdiv {a} {b})) \
                 (concat (bvurem {a} {b}) (bvudiv {a} {b}))))",
                a = arg(0),
                b = arg(1),
                zero = literal(0, n),
                none = literal(0, 2 * n),
                signed = bit(&arg(2))
            )
        }
        // The value under `n` copies of the fill, shifted as one word: what
        // comes down from above is the fill. The amount is clamped to `n`
        // first, so an amount no shift can express still shifts everything out.
        HwOp::Shr => {
            let n = width;
            let amount_width = data(1);
            let wide = 2 * n;
            let clamped = if amount_width > ceil_log2(n + 1) && amount_width <= wide {
                format!(
                    "(ite (bvuge {amount} {limit}) {all} ((_ zero_extend {pad}) {amount}))",
                    amount = arg(1),
                    limit = literal((n as u128) & mask(amount_width), amount_width),
                    all = literal(n as u128, wide),
                    pad = wide - amount_width
                )
            } else if amount_width > wide {
                format!(
                    "(ite (bvuge {amount} {limit}) {all} ((_ extract {top} 0) {amount}))",
                    amount = arg(1),
                    limit = literal(n as u128, amount_width),
                    all = literal(n as u128, wide),
                    top = wide - 1
                )
            } else {
                format!("((_ zero_extend {}) {})", wide - amount_width, arg(1))
            };
            format!(
                "((_ extract {top} 0) (bvlshr (concat ((_ repeat {n}) {fill}) {value}) {clamped}))",
                top = n - 1,
                fill = arg(2),
                value = arg(0)
            )
        }
        HwOp::Ror => {
            let n = width;
            let amount = format!("((_ zero_extend {}) {})", n - data(1), arg(1));
            format!(
                "(bvor (bvlshr {a} {amount}) (bvshl {a} (bvsub {n_lit} {amount})))",
                a = arg(0),
                n_lit = literal(n as u128, n)
            )
        }
        HwOp::Clz => {
            let n = data(0);
            let mut term = literal(n as u128, width);
            for index in 0..n {
                term = format!(
                    "(ite {} {} {term})",
                    bit(&format!("((_ extract {index} {index}) {})", arg(0))),
                    literal((n - 1 - index) as u128, width)
                );
            }
            term
        }
        HwOp::Cpop => {
            let n = data(0);
            let bits: Vec<String> = (0..n)
                .map(|index| {
                    let one = format!("((_ extract {index} {index}) {})", arg(0));
                    if width > 1 {
                        format!("((_ zero_extend {}) {one})", width - 1)
                    } else {
                        one
                    }
                })
                .collect();
            if bits.len() == 1 {
                bits[0].clone()
            } else {
                format!("(bvadd {})", bits.join(" "))
            }
        }
        HwOp::Eq => format!("(ite (= {} {}) #b1 #b0)", arg(0), arg(1)),
        HwOp::And => format!("(bvand {} {})", arg(0), arg(1)),
        HwOp::Or => format!("(bvor {} {})", arg(0), arg(1)),
        HwOp::Xor => format!("(bvxor {} {})", arg(0), arg(1)),
        HwOp::Not => format!("(bvnot {})", arg(0)),
        HwOp::Mux => format!("(ite {} {} {})", bit(&arg(0)), arg(1), arg(2)),
        HwOp::Zext => format!("((_ zero_extend {}) {})", width - data(0), arg(0)),
        HwOp::Sext => format!("((_ sign_extend {}) {})", width - data(0), arg(0)),
        HwOp::Slice => {
            let lo = node.value as u32;
            format!("((_ extract {} {lo}) {})", lo + width - 1, arg(0))
        }
        HwOp::Concat => format!("(concat {} {})", arg(0), arg(1)),
        HwOp::Rev => {
            let bits: Vec<String> = (0..width)
                .map(|index| format!("((_ extract {index} {index}) {})", arg(0)))
                .collect();
            format!("(concat {})", bits.join(" "))
        }
    }
}

fn smt_function(out: &mut String, graph: &HwGraph, name: &str, inputs: &[(String, u32)],
                select_width: u32, root: NodeId) {
    let mut parameters: HashMap<String, (String, u32)> = inputs
        .iter()
        .map(|(input, width)| (input.clone(), (format!("p_{}", smt_ident_of(input)), *width)))
        .collect();
    let mut signature: Vec<String> = inputs
        .iter()
        .map(|(input, width)| format!("({} (_ BitVec {width}))", parameters[input].0))
        .collect();
    if select_width > 0 {
        parameters.insert(SELECT_INPUT.to_string(), ("sel".to_string(), select_width));
        signature.insert(0, format!("(sel (_ BitVec {select_width}))"));
    }
    out.push_str(&format!(
        "(define-fun {name} ({}) (_ BitVec {})\n",
        signature.join(" "),
        graph.width(root)
    ));
    let cone = graph.cone(&[root]);
    for id in &cone {
        out.push_str(&format!("  (let ((n{id} {}))\n", smt_node(graph, *id, &parameters)));
    }
    out.push_str(&format!("  n{root}{})\n\n", ")".repeat(cone.len())));
}

/// `emit-smt2`'s definitions, and beside each the netlist that claims to
/// compute it: `axis_hw_<instruction>` over the same operands, and
/// `axis_hw_unit_<unit>` over a select and the unit's ports.
///
/// The comment lines starting `; axis-hw` are the index a prover reads, so it
/// does not have to re-derive which instruction is which function or which
/// code selects it.
pub fn emit_hw_smt2(document: &Document) -> String {
    emit_hw_smt2_planned(document, None).expect("AXIS's own plan is valid")
}

pub fn emit_hw_smt2_planned(document: &Document, plan: Option<&str>) -> Result<String, String> {
    emit_hw_smt2_at(document, plan, None)
}

pub fn emit_hw_smt2_at(document: &Document, plan: Option<&str>, cycle: Option<f64>)
    -> Result<String, String> {
    let (design, _, units) = planned(document, plan, cycle)?;
    let mut out = emit_smt2(document);
    out.push_str("\n; Netlists (emit-hw-smt2).\n\n");
    let identifiers: Vec<String> =
        builder_names(&design).iter().map(|name| name.replacen("build_", "axis_hw_", 1)).collect();
    for (datapath, identifier) in design.datapaths.iter().zip(&identifiers) {
        let Ok(root) = &datapath.root else { continue };
        let operands: Vec<String> = datapath
            .inputs
            .iter()
            .map(|(name, width)| format!("{}:{width}", smt_ident_of(name)))
            .collect();
        out.push_str(&format!(
            "; axis-hw instruction {} {} axis_instr_{} {} {}\n",
            json_string(&datapath.mnemonic),
            identifier,
            smt_ident_of(&datapath.mnemonic),
            datapath.output_width,
            operands.join(" ")
        ));
        smt_function(&mut out, &design.graph, identifier, &datapath.inputs, 0, *root);
    }
    for unit in &units {
        let identifier = format!("axis_hw_unit_{}", smt_ident_of(&unit.name));
        let ports: Vec<String> = unit
            .inputs
            .iter()
            .map(|(name, width)| format!("{}:{width}", smt_ident_of(name)))
            .collect();
        out.push_str(&format!(
            "; axis-hw unit {} {} {} {} {}\n",
            json_string(&unit.name),
            identifier,
            unit.select_width,
            unit.output_width,
            ports.join(" ")
        ));
        for (code, member) in unit.members.iter().enumerate() {
            out.push_str(&format!("; axis-hw member {identifier} {code} {}\n", identifiers[*member]));
        }
        smt_function(&mut out, &design.graph, &identifier, &unit.inputs, unit.select_width,
                     unit.root);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Units over effects (`docs/hardware_design.md` §3.5): the same netlists, with
// instructions stated as effects as members beside values. A separate pair of
// artifacts, so what `emit-hw-pyrtl` and `emit-hw-json` publish -- and what
// their consumers read -- does not move.

fn slot_units(document: &Document, cycle: Option<f64>) -> (HwDesign, Vec<SlotUnit>) {
    let mut design = lower_document(document);
    design.cycle = cycle;
    let groups = plan_slot_units(&mut design);
    let units = groups
        .iter()
        .map(|(name, members)| merge_slot_unit(&mut design, name, members))
        .collect();
    (design, units)
}

fn source_text(source: &SlotSource) -> String {
    match source {
        SlotSource::Result => "[\"result\", null]".to_string(),
        SlotSource::LoadAddr => "[\"load_addr\", null]".to_string(),
        SlotSource::Value(k) => format!("[\"value\", {k}]"),
        SlotSource::Guard(k) => format!("[\"guard\", {k}]"),
        SlotSource::Addr(k) => format!("[\"addr\", {k}]"),
    }
}

/// What each unit with effects in it is: its members, its slots, what each
/// member drives in each, and what it costs.
pub fn emit_hw_effect_json_at(document: &Document, cycle: Option<f64>) -> Result<String, String> {
    let (design, units) = slot_units(document, cycle);
    let budget = cycle_budget(&design);
    let rendered: Vec<String> = units
        .iter()
        .map(|unit| {
            let members: Vec<String> = unit
                .members
                .iter()
                .zip(&unit.sources)
                .map(|(member, sources)| {
                    let kind = match member {
                        MemberRef::Value(_) => "value",
                        MemberRef::Effect(_) => "effect",
                    };
                    let drives: Vec<String> = sources
                        .iter()
                        .map(|(slot, source)| format!("[{}, {}]", json_string(slot), source_text(source)))
                        .collect();
                    format!(
                        "{{\"mnemonic\": {}, \"kind\": \"{kind}\", \"drives\": [{}]}}",
                        json_string(member.mnemonic(&design)),
                        drives.join(", ")
                    )
                })
                .collect();
            let slots: Vec<String> = unit
                .slots
                .iter()
                .map(|(slot, width, _)| format!("[{}, {width}]", json_string(slot)))
                .collect();
            let instances: Vec<String> = unit
                .instances
                .iter()
                .filter(|instance| instance.nodes > 1)
                .map(|instance| {
                    format!(
                        "{{\"class\": {}, \"width\": {}, \"nodes\": {}}}",
                        json_string(instance.class),
                        instance.width,
                        instance.nodes
                    )
                })
                .collect();
            let kept: Vec<String> = unit
                .kept_apart
                .iter()
                .map(|kept| {
                    format!(
                        "{{\"class\": \"{}\", \"because\": \"{}\", \"removes\": {:.1}, \"saves\": {:.1}}}",
                        kept.class, kept.because, kept.removes, kept.saves
                    )
                })
                .collect();
            format!(
                "    {{\"name\": {}, \"latency\": {}, \"stage_delay\": {:.1}, \"select_width\": {}, \"inputs\": {}, \
                 \"slots\": [{}], \"area\": {{\"identical_shared\": {:.1}, \"merged\": {:.1}}}, \
                 \"depth\": {:.1}, \"shared\": [{}], \"kept_apart\": [{}],\n      \"members\": [\n        {}\n      ]}}",
                json_string(&unit.name),
                unit.latency,
                schedule_roots(
                    &design.graph,
                    &unit.slots.iter().map(|(_, _, node)| *node).collect::<Vec<_>>(),
                    unit.latency.saturating_sub(1)
                )
                .stage_delay,
                unit.select_width,
                json_inputs(&unit.inputs),
                slots.join(", "),
                unit.area_identical,
                unit.area_merged,
                unit.depth_merged,
                instances.join(", "),
                kept.join(", "),
                members.join(",\n        ")
            )
        })
        .collect();
    let total: f64 = units.iter().map(|unit| unit.area_merged).sum();
    Ok(format!(
        "{{\n  \"schema\": \"axis.hw-effect-units.v1\",\n  \"cost_model\": {{\"area_unit\": \
         \"nand2-equivalent\", \"delay_unit\": \"gate\", \"calibrated\": true, \"reference\": {}, \
         \"ps_per_gate\": {PS_PER_GATE:.1}, \"cycle_budget\": {budget:.1}}},\n  \
         \"machine_area\": {total:.1},\n  \"units\": [\n{}\n  ]\n}}\n",
        json_string(COST_REFERENCE),
        rendered.join(",\n")
    ))
}

/// The same units as PyRTL: `build_effect_unit_<name>(sel, ports...)` returns
/// every slot's wire by name, and `EFFECT_UNITS` says what each member drives.
pub fn emit_hw_effect_pyrtl_at(document: &Document, cycle: Option<f64>) -> Result<String, String> {
    let (design, units) = slot_units(document, cycle);
    let mut out = String::new();
    out.push_str("# Generated by AXIS. Functional units whose members may write registers,\n");
    out.push_str("# the program counter, memory and state: one output per slot.\n");
    out.push_str("import pyrtl\n\nAXIS_SCHEMA = \"axis.hw-effect-pyrtl.v1\"\n\n");
    out.push_str(PYRTL_PRELUDE);
    out.push_str("EFFECT_UNITS = {\n");
    for unit in &units {
        let members: Vec<String> = unit
            .members
            .iter()
            .zip(&unit.sources)
            .map(|(member, sources)| {
                let drives: Vec<String> = sources
                    .iter()
                    .map(|(slot, source)| {
                        let (kind, index) = match source {
                            SlotSource::Result => ("result", "None".to_string()),
                            SlotSource::LoadAddr => ("load_addr", "None".to_string()),
                            SlotSource::Value(k) => ("value", k.to_string()),
                            SlotSource::Guard(k) => ("guard", k.to_string()),
                            SlotSource::Addr(k) => ("addr", k.to_string()),
                        };
                        format!("({}, \"{kind}\", {index})", json_string(slot))
                    })
                    .collect();
                format!(
                    "({}, \"{}\", [{}])",
                    json_string(member.mnemonic(&design)),
                    if matches!(member, MemberRef::Value(_)) { "value" } else { "effect" },
                    drives.join(", ")
                )
            })
            .collect();
        let slots: Vec<String> =
            unit.slots.iter().map(|(slot, width, _)| format!("({}, {width})", json_string(slot))).collect();
        out.push_str(&format!(
            "    {}: {{\"builder\": {}, \"pipelined_builder\": {}, \"latency\": {}, \
             \"select_width\": {}, \"inputs\": {}, \"slots\": [{}], \"members\": [{}]}},\n",
            json_string(&unit.name),
            json_string(&format!("build_effect_unit_{}", python_ident(&unit.name))),
            json_string(&format!("build_effect_unit_{}_pipelined", python_ident(&unit.name))),
            unit.latency,
            unit.select_width,
            python_inputs(&unit.inputs),
            slots.join(", "),
            members.join(", ")
        ));
    }
    out.push_str("}\n\n");
    for unit in &units {
        let names = parameter_names(&unit.inputs);
        let mut parameters: HashMap<String, String> =
            unit.inputs.iter().map(|(name, _)| name.clone()).zip(names.iter().cloned()).collect();
        parameters.insert(SELECT_INPUT.to_string(), "sel".to_string());
        let mut signature = names.clone();
        if unit.select_width > 0 {
            signature.insert(0, "sel".to_string());
        }
        out.push_str(&format!(
            "def build_effect_unit_{}({}):\n",
            python_ident(&unit.name),
            signature.join(", ")
        ));
        let roots: Vec<NodeId> = unit.slots.iter().map(|(_, _, node)| *node).collect();
        let returns: Vec<String> = unit
            .slots
            .iter()
            .enumerate()
            .map(|(index, (slot, _, _))| format!("{}: @{index}", json_string(slot)))
            .collect();
        let returns = format!("{{{}}}", returns.join(", "));
        emit_cones(&mut out, &design.graph, &roots, &parameters, None, Some(&returns));
        // The same unit in time: every slot leaves after the unit's latency
        // less one register, a new instruction accepted every cycle, and a
        // valid bit beside them saying which cycles carry one.
        signature.insert(0, "valid".to_string());
        out.push_str(&format!(
            "def build_effect_unit_{}_pipelined({}):\n",
            python_ident(&unit.name),
            signature.join(", ")
        ));
        let plan = schedule_roots(&design.graph, &roots, unit.latency.saturating_sub(1));
        emit_cones(&mut out, &design.graph, &roots, &parameters, Some(&plan), Some(&returns));
    }
    Ok(out)
}
