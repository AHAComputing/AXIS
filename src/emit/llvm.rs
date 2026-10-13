//! AXIS emit: llvm domain (split from the former monolithic emit.rs).

use super::common::*;

/// Emit a self-contained LLVM IR module: one `define i32 @axis_eval_<name>`
/// per instruction/accelerator with `formal_semantics`, lowered from the same
/// typed IR the C interpreter uses and bit-identical to it. The width-sensitive
/// operations (`shl`/rotate/`clz`/…/extend) call the fixed `axis_sem_*` helper
/// `define`s in the prelude, whose masking discipline mirrors
/// `C_SEMANTICS_HELPERS` exactly. `tools/llvm_vs_golden.py` proves the match.
/// The stencil module: every instruction as a function with its operands left
/// as holes, for a copy-and-patch JIT.
///
/// ⚠️ This lived in `tools/jit_stencil.py`, which built it by regex-rewriting
/// the output of `emit-llvm-ir`. That is why there was no stencil *library*:
/// the artifact a library would be built from was assembled inside a gate. The
/// technique was proven there -- 264 patched stencils agreeing with the golden
/// model -- and never productised, exactly as the decoder was before packs.
///
/// A hole is a symbol the stencil references. The compiler, not knowing its
/// address, emits a relocation; the object's relocation table then says where
/// in the bytes that value is referenced and how it is encoded, and the
/// patcher writes the real value there.
pub fn emit_stencil_ll(document: &Document) -> String {
    let semantics = crate::emit::llvm::emit_llvm_ir(document);
    // The handlers become internal and always-inlined, so a stencil's bytes are
    // self-contained: no call, no frame, nothing to resolve but the holes. Left
    // external, LLVM keeps the call and the stencil comes out with a prologue
    // and a branch that copying the bytes would not bring along.
    let mut body = String::new();
    let mut widths: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut effect_widths: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    for line in semantics.lines() {
        // ⚠️ `@axis_eval_` specifically. `strip_prefix("define i")` also
        // matches `define internal ...`, because "internal" begins with an
        // `i` -- which turned every already-internal helper into
        // `define internal internal i32`, and LLVM said so.
        let rewritten = if let Some(rest) = line
            .strip_prefix("define i")
            .filter(|_| line.contains(" @axis_eval_"))
        {
            if let Some((bits, tail)) = rest.split_once(" @axis_eval_") {
                if let (Ok(bits), Some((name, _))) = (bits.parse::<u32>(), tail.split_once('(')) {
                    widths.insert(name.to_string(), bits);
                }
            }
            format!("{} alwaysinline {{", line.trim_end_matches(" {").replacen("define ", "define internal ", 1))
        } else if line.starts_with("@AXIS_HOLE_memory_mask = internal global") {
            // ⚠️ The one line that differs between the two modules. Internal
            // and all-ones, a mask is the identity and the optimiser removes
            // it; external, it is a relocation, and a relocation whose name
            // ends `_mask` is a hole the table fills from the machine.
            AXIS_MEMORY_MASK_DECLARATION.trim_end().to_string()
        } else if line.starts_with("define void @axis_eff_") {
            if let Some((name, rest)) = line["define void @axis_eff_".len()..].split_once('(') {
                if let Some(pc) = rest.split("i8* %mem, i").nth(1) {
                    if let Some((bits, _)) = pc.split_once(" %pc") {
                        if let Ok(bits) = bits.parse::<u32>() {
                            effect_widths.insert(name.to_string(), bits);
                        }
                    }
                }
            }
            format!("{} alwaysinline {{", line.trim_end_matches(" {").replacen("define ", "define internal ", 1))
        } else {
            line.to_string()
        };
        body.push_str(&rewritten);
        body.push('\n');
    }

    let mut declarations: Vec<String> = Vec::new();
    let mut stencils = String::from("\n; --- stencils ---\n");
    // ⚠️ Every decline names its cause. This emitter refused silently, so the
    // only way to learn why two thirds of an architecture had no stencil was
    // to guess from the class names and be wrong about which rule fired -- the
    // first count blamed `rv_fpr` for 137 instructions that are actually
    // refused for writing a state slot.
    let mut declined: Vec<(String, String)> = Vec::new();
    // The ordered slots an alias resolves against, and the order the machine's
    // own state array is in.
    let state_slots = crate::effects::isa_scalar_state_slots(&document.isas);
    let declare = |declarations: &mut Vec<String>, hole: &str| {
        declarations.push(format!("@{hole} = external dso_local global i8"));
    };
    for instruction in architectural_instructions(document) {
        let ident = tablegen_ident(&instruction.mnemonic).to_lowercase();
        if let Some(width) = stencil_effect_width(&instruction, &effect_widths) {
            match instruction
                .operands
                .iter()
                .find_map(stencil_class_objection)
            {
                Some(objection) => declined.push((ident.clone(), objection)),
                None => {
                    stencil_effect(
                        &instruction,
                        &ident,
                        width,
                        &state_slots,
                        &mut declarations,
                        &mut stencils,
                    )
                }
            }
            continue;
        }
        let Some(&width) = widths.get(&ident) else {
            declined.push((
                ident.clone(),
                match stencil_effect_reason(&instruction) {
                    Some(reason) => reason,
                    None => "no value expression this build lowers".to_string(),
                },
            ));
            continue;
        };
        let inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| !matches!(crate::ast::operand_role(operand, false), "out" | "enc"))
            .collect();
        let dest = instruction.operands.iter().find(|operand| operand.output);
        if dest.is_none() || inputs.is_empty() {
            declined.push((
                ident.clone(),
                if dest.is_none() {
                    "it writes no register".to_string()
                } else {
                    "it reads no operand".to_string()
                },
            ));
            continue;
        }
        // A class this cannot model is a stencil this must not emit.
        let touched: Vec<&Operand> = inputs.iter().copied().chain(dest).collect();
        // ⚠️ A pure-value stencil passes ONE slot per operand and commits one.
        // The effect path takes limbs -- the handler's ABI is limbs, low first,
        // and its scratch reports one position each -- but this path hands the
        // eval function a single word, and there is no shape here for joining
        // two into an `i128` and splitting the answer back. Declined by name
        // rather than emitted as a `trunc i64 ... to i128`, which is what it
        // was doing the moment the class objection stopped refusing these.
        let wide = touched
            .iter()
            .copied()
            .find(|operand| stencil_value_limbs(operand) > 1);
        if let Some(objection) = touched
            .iter()
            .copied()
            .find_map(stencil_class_objection)
            .or_else(|| stencil_alias_objection(&touched, &state_slots))
            .or_else(|| {
                wide.map(|operand| {
                    format!(
                        "`{}` carries {} slots, and a value stencil passes one",
                        operand.kind,
                        stencil_value_limbs(operand)
                    )
                })
            })
        {
            declined.push((ident.clone(), objection));
            continue;
        }
        // ⚠️ The register file arrives through a hole, not through a register.
        // A stencil is a standalone function as far as the compiler is
        // concerned, free to clobber the argument registers; a block that
        // concatenated them and assumed one survived would be relying on luck
        // rather than on a rule. Reached through a hole, every stencil is
        // position-independent and composes whatever the allocator did.
        declare(&mut declarations, &format!("AXIS_HOLE_{ident}_regs"));
        let mut lines = vec![format!(
            "  %regs = load i64*, i64** bitcast (i8* @AXIS_HOLE_{ident}_regs to i64**)"
        )];
        // ⚠️ The state pointer only when something aliases. A stencil that
        // loads it unconditionally has a `state` hole, and the simulator
        // refuses a stencil that reads state -- so an unused load would cost
        // every stencil in the module its place in a translated block.
        let aliases = touched
            .iter()
            .any(|operand| stencil_alias(operand, &state_slots).is_some());
        if aliases {
            declare(&mut declarations, &format!("AXIS_HOLE_{ident}_state"));
            lines.push(format!(
                "  %state = load i64*, i64** bitcast (i8* @AXIS_HOLE_{ident}_state to i64**)"
            ));
        }
        for (position, operand) in inputs.iter().enumerate() {
            declare(&mut declarations, &format!("AXIS_HOLE_{ident}_{position}"));
            lines.push(format!(
                "  %s{position} = load i64, i64* bitcast (i8* @AXIS_HOLE_{ident}_{position} to i64*)"
            ));
            if operand.kind == "imm" {
                // An immediate is the simpler hole: the slot holds the value
                // itself rather than where to find it. Same patching, one
                // indirection less.
                lines.push(format!("  %w{position} = bitcast i64 %s{position} to i64"));
            } else {
                let (base, stride, zero) = stencil_slot_shape(operand);
                lines.push(format!("  %n{position} = mul i64 %s{position}, {stride}"));
                lines.push(format!("  %i{position} = add i64 %n{position}, {base}"));
                lines.push(format!(
                    "  %p{position} = getelementptr i64, i64* %regs, i64 %i{position}"
                ));
                lines.push(format!("  %l{position} = load i64, i64* %p{position}"));
                match (zero, stencil_alias(operand, &state_slots)) {
                    // The hardwired zero reads as zero whatever the slot holds.
                    (Some(index), _) => {
                        lines.push(format!("  %zc{position} = icmp eq i64 %s{position}, {index}"));
                        lines.push(format!(
                            "  %w{position} = select i1 %zc{position}, i64 0, i64 %l{position}"
                        ));
                    }
                    // ⚠️ And the aliased index reads the STATE slot, not the
                    // register file. Branchless, like the zero: a branch in a
                    // stencil is a relocation the patcher would have to
                    // understand, and there is a `select` that does it.
                    (None, Some((index, slot))) => {
                        lines.push(format!("  %ac{position} = icmp eq i64 %s{position}, {index}"));
                        lines.push(format!(
                            "  %ap{position} = getelementptr i64, i64* %state, i64 {slot}"
                        ));
                        lines.push(format!("  %av{position} = load i64, i64* %ap{position}"));
                        lines.push(format!(
                            "  %w{position} = select i1 %ac{position}, i64 %av{position}, i64 %l{position}"
                        ));
                    }
                    (None, None) => {
                        lines.push(format!("  %w{position} = bitcast i64 %l{position} to i64"))
                    }
                }
                // ⚠️ And the class's VIEW. `a64_gpr32` is the W half of an X,
                // and this read handed the whole X to a handler that expects
                // thirty-two bits -- invisible while every operand of a
                // stencilled instruction shared one width, and wrong the
                // moment `add x0, sp, w8, sxtx` got a stencil, because there
                // the machine is 64 bits and one source is 32.
                if let Some(view) = crate::ast::register_class(&operand.kind)
                    .and_then(|class| class.view_width)
                    .filter(|view| *view < 64)
                {
                    let mask = (1u64 << view) - 1;
                    lines.push(format!(
                        "  %m{position} = and i64 %w{position}, {mask}"
                    ));
                    lines.push(format!(
                        "  %w{position}v = bitcast i64 %m{position} to i64"
                    ));
                }
            }
            let viewed = if operand.kind != "imm"
                && crate::ast::register_class(&operand.kind)
                    .and_then(|class| class.view_width)
                    .is_some_and(|view| view < 64)
            {
                format!("%w{position}v")
            } else {
                format!("%w{position}")
            };
            if width == 64 {
                lines.push(format!("  %v{position} = bitcast i64 {viewed} to i64"));
            } else {
                lines.push(format!("  %v{position} = trunc i64 {viewed} to i{width}"));
            }
        }
        declare(&mut declarations, &format!("AXIS_HOLE_{ident}_dest"));
        let args = (0..inputs.len())
            .map(|i| format!("i{width} %v{i}"))
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("  %r = call i{width} @axis_eval_{ident}({args})"));
        if width == 64 {
            lines.push("  %rw = bitcast i64 %r to i64".to_string());
        } else {
            lines.push(format!("  %rw = zext i{width} %r to i64"));
        }
        lines.push(format!(
            "  %d = load i64, i64* bitcast (i8* @AXIS_HOLE_{ident}_dest to i64*)"
        ));
        let (base, stride, zero) = stencil_slot_shape(dest.expect("checked above"));
        lines.push(format!("  %dn = mul i64 %d, {stride}"));
        lines.push(format!("  %di = add i64 %dn, {base}"));
        lines.push("  %dp = getelementptr i64, i64* %regs, i64 %di".to_string());
        let destination = dest.expect("checked above");
        match (zero, stencil_alias(destination, &state_slots)) {
            // A write to the hardwired zero is discarded. Written branchlessly:
            // a stencil with a branch in it is a stencil with a relocation the
            // patcher would have to understand.
            (Some(index), _) => {
                lines.push(format!("  %dz = icmp eq i64 %d, {index}"));
                lines.push("  %old = load i64, i64* %dp".to_string());
                lines.push("  %keep = select i1 %dz, i64 %old, i64 %rw".to_string());
                lines.push("  store i64 %keep, i64* %dp".to_string());
            }
            // ⚠️ The aliased index is written by selecting the ADDRESS, not the
            // value: one store either way, and no branch. Selecting the value
            // instead would mean two stores, one of which writes a register the
            // instruction did not name.
            (None, Some((index, slot))) => {
                lines.push(format!("  %da = icmp eq i64 %d, {index}"));
                lines.push(format!("  %dap = getelementptr i64, i64* %state, i64 {slot}"));
                lines.push("  %dt = select i1 %da, i64* %dap, i64* %dp".to_string());
                lines.push("  store i64 %rw, i64* %dt".to_string());
            }
            (None, None) => lines.push("  store i64 %rw, i64* %dp".to_string()),
        }
        // ⚠️ The rest of the register, as above: a class whose registers take
        // more than one slot has bits outside the value it just wrote, and its
        // policy says they are zero. `ucvtf d0, w1` is the pure-value twin of
        // `ldr d0` and needed the same thing -- it was found the same way, one
        // gate run later.
        let aliased = stencil_alias(destination, &state_slots).is_some();
        if stride > 1 && !aliased {
            for limb in 1..stride {
                lines.push(format!("  %hi{limb} = add i64 %di, {limb}"));
                lines.push(format!(
                    "  %hp{limb} = getelementptr i64, i64* %regs, i64 %hi{limb}"
                ));
                match zero {
                    // A write the hardwired zero discards clears nothing.
                    Some(index) => {
                        lines.push(format!("  %hz{limb} = icmp eq i64 %d, {index}"));
                        lines.push(format!("  %hold{limb} = load i64, i64* %hp{limb}"));
                        lines.push(format!(
                            "  %hnew{limb} = select i1 %hz{limb}, i64 %hold{limb}, i64 0"
                        ));
                        lines.push(format!("  store i64 %hnew{limb}, i64* %hp{limb}"));
                    }
                    None => lines.push(format!("  store i64 0, i64* %hp{limb}")),
                }
            }
        }
        stencils.push_str(&format!(
            "define void @axis_stencil_{ident}() {{\nentry:\n{}\n  ret void\n}}\n",
            lines.join("\n")
        ));
    }

    let mut out = String::from("; Generated by AXIS. Stencils: one per instruction, operands as holes.\n");
    out.push_str("; schema: axis.stencil-ll.v1\n");
    for line in &declarations {
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&body);
    out.push_str(&stencils);
    // ⚠️ In the module, as comments, so the reason travels with the artifact
    // rather than living in whatever tool last asked. `jit_table.py` reads this
    // file already.
    if !declined.is_empty() {
        out.push_str(&format!(
            "\n; --- no stencil, and why ({} instruction(s)) ---\n",
            declined.len()
        ));
        for (ident, reason) in &declined {
            out.push_str(&format!("; declined {ident}: {reason}\n"));
        }
    }
    out
}


/// The machine width of this instruction's effect handler, when a stencil can
/// carry every effect it has.
///
/// Loads and stores can: they write a register and memory and nothing else. A
/// branch writes the pc and a trap ends the block, and both are the block's
/// business rather than a stencil's. `setstate` is left out because syncing
/// architectural state across the handoff is a separate thing to get right.
/// What an operand's register class asks for that a stencil cannot say.
///
/// ⚠️ A stencil indexes a flat array of 64-bit slots and nothing else. The
/// class table knows about more than that -- files that start part-way up the
/// array, three-bit fields that name `x8`-`x15`, a hardwired zero, a view that
/// preserves the bits around it, registers that take two slots. The first two
/// and the third a stencil can carry, because they are arithmetic on the index
/// and a comparison against it. The rest it cannot, and an instruction whose
/// operands need them gets no stencil at all.
///
/// This was found by running a translated `c.sub` against the executor beside
/// it: the stencil wrote the register the field named, and the architecture
/// says that field's 1 is `x9`. Every earlier stencil check indexed the file
/// raw on both sides, so both were wrong together and agreed.
fn stencil_class_objection(operand: &Operand) -> Option<String> {
    if operand.kind == "imm" {
        return None;
    }
    let Some(class) = crate::ast::register_class(&operand.kind) else {
        return Some(format!("`{}` names no register class", operand.kind));
    };
    // ⚠️ How many SLOTS a register takes is no longer a refusal -- the stencils
    // stride by it now. How many slots its VALUE takes still is: an operand
    // wider than a slot arrives at the handler as limbs, and a stencil that
    // passed one word would be handing a 128-bit instruction half its input.
    // `a64_vreg64` is two slots per register and sixty-four bits of value, and
    // that is the common case this separation lets through.
    // ⚠️ A value wider than a slot arrives as limbs, low first, and the stencil
    // reads and commits each -- so the limit is the SCRATCH's, not the slot's.
    // What is still refused is a wide value that also needs one of the
    // per-slot rules below, because "the low limb of a view at bit 8" is a
    // sentence this has no shape for and nothing has ever asked for.
    let value_bits = class.view_width.unwrap_or_else(|| class.file_width.unwrap_or(64));
    let limbs = value_bits.div_ceil(64).max(1);
    if limbs as usize > crate::effects::EFFECT_MAX_WRITES {
        return Some(format!(
            "`{}` carries {value_bits} bits, and the scratch holds {}",
            class.name,
            crate::effects::EFFECT_MAX_WRITES * 64
        ));
    }
    if limbs > 1 && (class.zero_index.is_some() || class.alias.is_some()) {
        return Some(format!(
            "`{}` is {value_bits} bits and has a special index",
            class.name
        ));
    }
    // ⚠️ An alias is no longer refused. It was 436 of AArch64's 734 declines --
    // three fifths of one architecture for a rule that costs a compare and a
    // select -- because `a64_gpr64sp` is how the base of every stack-relative
    // load, store, add and compare is spelled. The slot it names has to be one
    // the ISA declares, which `stencil_alias` checks where the slots are known.
    if !matches!(class.write_policy, crate::ast::WritePolicy::Zero) {
        return Some(format!("`{}` preserves the bits outside its view", class.name));
    }
    if class.view_offset != 0 {
        return Some(format!("`{}` views a register from bit {}", class.name, class.view_offset));
    }

    None
}

/// Where a class's index lands in the flat register array, and whether it reads
/// as zero. The same arithmetic the lifter does: `offset + index_offset + i`.
/// Where a class's index lands, as the two numbers it actually takes.
///
/// ⚠️ `base + index * stride`, not `base + index`. A register that occupies
/// more than one slot strides by its limb count, and the stencils spelled the
/// scalar case -- which is why every class with two slots per register had to
/// be refused rather than indexed wrongly. The same arithmetic the lifter does
/// and the layout publishes: `offset + (index_offset + index) * limbs`.
fn stencil_slot_shape(operand: &Operand) -> (u64, u64, Option<u32>) {
    match crate::ast::register_class(&operand.kind) {
        Some(class) => {
            let stride = u64::from(class.limbs.max(1));
            (
                u64::from(class.offset) + u64::from(class.index_offset) * stride,
                stride,
                class.zero_index,
            )
        }
        None => (0, 1, None),
    }
}

/// How many slots this operand's VALUE occupies.
///
/// ⚠️ Not the same as how many its register occupies. `a64_vreg64` is two slots
/// per register and one slot of value -- the D view of a Q -- while
/// `a64_vreg128` is two of each. The handler takes one parameter per slot of
/// value, low first, and reports a write into one scratch position per slot,
/// so this is the number both sides count in.
fn stencil_value_limbs(operand: &Operand) -> u64 {
    let bits = crate::ast::register_class(&operand.kind)
        .map(|class| {
            class
                .view_width
                .unwrap_or_else(|| class.file_width.unwrap_or(64))
        })
        .unwrap_or(64);
    u64::from(bits.div_ceil(64)).max(1)
}

/// The index this operand's class aliases, and which state slot it names.
///
/// ⚠️ The slot NUMBER, not the name: a stencil is machine code with a pointer
/// patched into it, so it reaches state by offset from that pointer and the
/// name has to be resolved while there is still a description to ask. The
/// order is the one `isa_scalar_state_slots` gives, which is the order the pack
/// publishes and the order the simulator's own array is in -- three places that
/// have to agree, and would silently read the wrong slot if they ever did not.
fn stencil_alias(operand: &Operand, state: &[(String, u32)]) -> Option<(u32, usize)> {
    let class = crate::ast::register_class(&operand.kind)?;
    let (index, name) = class.alias?;
    let slot = state.iter().position(|(slot, _)| slot == name)?;
    Some((index, slot))
}

/// Whether every alias among these operands names a slot this ISA declares.
fn stencil_alias_objection(
    operands: &[&Operand],
    state: &[(String, u32)],
) -> Option<String> {
    for operand in operands {
        let Some(class) = crate::ast::register_class(&operand.kind) else {
            continue;
        };
        let Some((_, name)) = class.alias else { continue };
        if !state.iter().any(|(slot, _)| slot == name) {
            return Some(format!(
                "`{}` aliases the state slot `{name}`, which this ISA does not declare",
                class.name
            ));
        }
    }
    None
}

/// Why an instruction with effects gets no effect stencil.
///
/// The same walk `stencil_effect_width` does, saying what it found rather than
/// returning `None`. Two answers that look alike from outside -- "it writes
/// state" and "it has no lowered handler" -- send a JIT to different places,
/// and only one of them is about this build.
fn stencil_effect_reason(instruction: &Instruction) -> Option<String> {
    let behavior = instruction.behavior.as_ref()?;
    if behavior.effects.is_empty() {
        return None;
    }
    let mut sets = 0;
    for effect in &behavior.effects {
        match &effect.loc {
            // ⚠️ Counted in SLOTS of value: one `ldr q0` is one effect and two
            // scratch positions, so counting effects let a pair of them past a
            // budget of four that they overran.
            crate::effects::Loc::Reg(name) => {
                sets += instruction
                    .operands
                    .iter()
                    .find(|operand| &operand.name == name)
                    .map_or(1, |operand| stencil_value_limbs(operand) as usize)
            }
            crate::effects::Loc::Mem { .. } => {}
            // ⚠️ Not a cause any more. A state write is carried, and leaving
            // this arm here made ten instructions report a reason that had
            // stopped being true -- which is worse than no reason, because a
            // reader acts on it. What refuses them is the last line.
            crate::effects::Loc::State { .. } => {}
            crate::effects::Loc::FixedReg { .. } => sets += 1,
            crate::effects::Loc::Barrier { kind, .. } => {
                return Some(format!("it is a `{kind}` barrier"))
            }
            // ⚠️ A send leaves the machine through a host's hook, and a stencil
            // is machine code with no call in it. Declined by name rather than
            // translated into a store to somewhere plausible.
            crate::effects::Loc::Port { .. } => {
                return Some("it posts a message, which needs a call".to_string())
            }
            // Not a cause any more: see `stencil_effect_width`.
            crate::effects::Loc::Pc => {}
            crate::effects::Loc::Trap => return Some("it traps".to_string()),
        }
    }
    if sets > crate::effects::EFFECT_MAX_WRITES {
        return Some(format!(
            "it writes {sets} registers, and the scratch carries {}",
            crate::effects::EFFECT_MAX_WRITES
        ));
    }
    Some("no lowered effect handler for it".to_string())
}

fn stencil_effect_width(
    instruction: &Instruction,
    widths: &std::collections::BTreeMap<String, u32>,
) -> Option<u32> {
    let behavior = instruction.behavior.as_ref()?;
    if behavior.effects.is_empty() {
        return None;
    }
    let mut sets = 0;
    for effect in &behavior.effects {
        match &effect.loc {
            // ⚠️ Counted in SLOTS of value: one `ldr q0` is one effect and two
            // scratch positions, so counting effects let a pair of them past a
            // budget of four that they overran.
            crate::effects::Loc::Reg(name) => {
                sets += instruction
                    .operands
                    .iter()
                    .find(|operand| &operand.name == name)
                    .map_or(1, |operand| stencil_value_limbs(operand) as usize)
            }
            crate::effects::Loc::Mem { .. } => {}
            // ⚠️ A state write is carried now. The handler has always done it
            // -- `adds` stores its flag word through the `%state` pointer it is
            // given -- and what was missing was somewhere for that pointer to
            // point: the simulator passed a scratch array nothing filled. It
            // copies the machine's named entries in and out around a block now,
            // so the stencil writes the same slot the interpreter does.
            //
            // This was 125 of AArch64's declines: `nzcv` alone is 79, which is
            // every instruction that sets a flag.
            crate::effects::Loc::State { .. } => {}
            // ⚠️ A branch is carried now, and carries ITSELF: every handler
            // already computes the next pc into the scratch -- `pc + 4` when
            // nothing branches, the target when something does, a `select`
            // when a guard decides -- so a stencil for a branch needs to emit
            // nothing extra. What it needs is for the block to END there, and
            // that is the simulator's to enforce, because a block is
            // straight-line code and the instructions after a taken branch
            // would run anyway.
            crate::effects::Loc::Pc => {}
            // ⚠️ A register the INSTRUCTION names rather than the word: `bl`
            // writes x30 whatever its encoding says. It takes a write slot like
            // any other and needs no hole, the index being a constant the
            // description already fixed.
            crate::effects::Loc::FixedReg { .. } => sets += 1,
            _ => return None,
        }
    }
    // ⚠️ Up to what the scratch carries. Each write is one more hole and one
    // more pair of slots, and the handler already fills them -- but four is
    // where `EFFECT_OUT_SLOTS` stops, so a fifth would be a stencil reading
    // past the array a caller sized from that constant.
    if sets > crate::effects::EFFECT_MAX_WRITES {
        return None;
    }
    widths
        .get(&tablegen_ident(&instruction.mnemonic).to_lowercase())
        .copied()
}

/// A stencil around `axis_eff_*`: the machine pointers arrive as holes.
///
/// The handler does its own memory accesses and reports its writes through a
/// scratch array, so the stencil's work is binding the operands and committing
/// the register write the handler says it made.
fn stencil_effect(
    instruction: &Instruction,
    ident: &str,
    width: u32,
    state_slots: &[(String, u32)],
    declarations: &mut Vec<String>,
    out: &mut String,
) {
    let machine = format!("i{width}");
    let mut lines: Vec<String> = Vec::new();
    for (label, kind) in [
        ("regs", "i64*".to_string()),
        ("mem", "i8*".to_string()),
        ("out", format!("{machine}*")),
        ("state", format!("{machine}*")),
        ("pc", machine.clone()),
    ] {
        declarations.push(format!("@AXIS_HOLE_{ident}_{label} = external dso_local global i8"));
        lines.push(format!(
            "  %{label} = load {kind}, {kind}* bitcast (i8* @AXIS_HOLE_{ident}_{label} to {kind}*)"
        ));
    }
    let inputs: Vec<&Operand> = instruction
        .operands
        .iter()
        .filter(|operand| !matches!(crate::ast::operand_role(operand, false), "out" | "enc"))
        .collect();
    let mut args: Vec<String> = Vec::new();
    for (position, operand) in inputs.iter().enumerate() {
        // Same rule as the pure stencils: a hole holds the field the
        // instruction encodes, and the stencil is what turns it into a slot.
        declarations.push(format!(
            "@AXIS_HOLE_{ident}_op{position} = external dso_local global i8"
        ));
        lines.push(format!(
            "  %s{position} = load i64, i64* bitcast (i8* @AXIS_HOLE_{ident}_op{position} to i64*)"
        ));
        let raw = if operand.kind == "imm" {
            format!("%s{position}")
        } else {
            let (base, stride, zero) = stencil_slot_shape(operand);
            lines.push(format!("  %n{position} = mul i64 %s{position}, {stride}"));
            lines.push(format!("  %i{position} = add i64 %n{position}, {base}"));
            lines.push(format!(
                "  %p{position} = getelementptr i64, i64* %regs, i64 %i{position}"
            ));
            lines.push(format!("  %l{position} = load i64, i64* %p{position}"));
            match (zero, stencil_alias(operand, state_slots)) {
                (Some(index), _) => {
                    lines.push(format!("  %zc{position} = icmp eq i64 %s{position}, {index}"));
                    lines.push(format!(
                        "  %v{position} = select i1 %zc{position}, i64 0, i64 %l{position}"
                    ));
                }
                // The aliased index reads the state slot the class names.
                (None, Some((index, slot))) => {
                    lines.push(format!("  %ac{position} = icmp eq i64 %s{position}, {index}"));
                    lines.push(format!(
                        "  %ap{position} = getelementptr i64, i64* %state, i64 {slot}"
                    ));
                    lines.push(format!("  %av{position} = load i64, i64* %ap{position}"));
                    lines.push(format!(
                        "  %v{position} = select i1 %ac{position}, i64 %av{position}, i64 %l{position}"
                    ));
                }
                (None, None) => {
                    lines.push(format!("  %v{position} = bitcast i64 %l{position} to i64"))
                }
            }
            // ⚠️ And the class's view. An effect handler for `add x0, sp, w8`
            // is given `w8` and computes at sixty-four; handing it the whole
            // `x8` was invisible until this instruction had a stencil at all.
            match crate::ast::register_class(&operand.kind)
                .and_then(|class| class.view_width)
                .filter(|view| *view < 64)
            {
                Some(view) => {
                    let mask = (1u64 << view) - 1;
                    lines.push(format!("  %m{position} = and i64 %v{position}, {mask}"));
                    format!("%m{position}")
                }
                None => format!("%v{position}"),
            }
        };
        if width == 64 {
            args.push(format!("{machine} {raw}"));
        } else {
            lines.push(format!("  %a{position} = trunc i64 {raw} to {machine}"));
            args.push(format!("{machine} %a{position}"));
        }
        // ⚠️ The limbs above the first, low one already passed. They sit in the
        // slots after it -- a register's limbs are consecutive -- and the
        // handler takes one parameter each, so a stencil that passed only the
        // low one would hand a 128-bit instruction half its input and get a
        // plausible answer about the wrong value.
        if operand.kind != "imm" {
            for limb in 1..stencil_value_limbs(operand) {
                lines.push(format!(
                    "  %hi{position}_{limb} = add i64 %i{position}, {limb}"
                ));
                lines.push(format!(
                    "  %hp{position}_{limb} = getelementptr i64, i64* %regs, i64 %hi{position}_{limb}"
                ));
                lines.push(format!(
                    "  %hl{position}_{limb} = load i64, i64* %hp{position}_{limb}"
                ));
                if width == 64 {
                    args.push(format!("{machine} %hl{position}_{limb}"));
                } else {
                    lines.push(format!(
                        "  %ha{position}_{limb} = trunc i64 %hl{position}_{limb} to {machine}"
                    ));
                    args.push(format!("{machine} %ha{position}_{limb}"));
                }
            }
        }
    }
    let mut call = vec![
        "i8* %mem".to_string(),
        format!("{machine} %pc"),
        format!("{machine}* %out"),
        format!("{machine}* %state"),
    ];
    call.extend(args);
    lines.push(format!(
        "  call void @axis_eff_{ident}({})",
        call.join(", ")
    ));
    // ⚠️ Every register this instruction writes, not the first. The handler has
    // always reported up to four -- `EFFECT_OUT_SLOTS` lays them out, and the
    // lift table publishes each one with the operand it lands in -- and a
    // stencil that committed only write 0 would silently drop the other half of
    // an `ldp`. This was 68 of AArch64's declines: every load pair, store pair
    // and writeback form it has.
    // ⚠️ Where each write LANDS, which is one of two things. An operand write
    // needs a hole, because the index is in the instruction; a fixed one --
    // `bl` writing x30 -- needs none, because the index is in the description
    // and the slot can be computed while there is still a description to ask.
    enum Landing<'a> {
        Operand(&'a Operand),
        Fixed { kind: &'a str, index: u32 },
    }
    let destinations: Vec<Landing> = instruction
        .behavior
        .as_ref()
        .map(|behavior| {
            behavior
                .effects
                .iter()
                .filter_map(|effect| match &effect.loc {
                    crate::effects::Loc::Reg(name) => instruction
                        .operands
                        .iter()
                        .find(|operand| &operand.name == name)
                        .map(Landing::Operand),
                    crate::effects::Loc::FixedReg { kind, index, .. } => {
                        Some(Landing::Fixed { kind, index: *index })
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    // ⚠️ One commit per SLOT of value, not per effect. A 128-bit write reports
    // into two scratch positions -- the handler splits it, low limb first --
    // and lands in two consecutive register slots. Iterating effects committed
    // the low limb and left the high one in the scratch, which is a `ldr q0`
    // that loaded half a register.
    let commits: Vec<(usize, u64)> = destinations
        .iter()
        .enumerate()
        .flat_map(|(which, landing)| {
            let limbs = match landing {
                Landing::Operand(operand) => stencil_value_limbs(operand),
                Landing::Fixed { .. } => 1,
            };
            (0..limbs).map(move |limb| (which, limb))
        })
        .collect();
    for (write, (which, limb)) in commits.iter().copied().enumerate() {
        let destination = &destinations[which];
        let last_limb = write + 1 == commits.len() || commits[write + 1].0 != which;
        // The layout `EFFECT_OUT_SLOTS` fixes: write 0 is slots 0 and 1, and
        // the rest follow the pc and the trap id in pairs.
        let (value_slot, wrote_slot) = if write == 0 {
            (0, 1)
        } else {
            (2 + 2 * write, 3 + 2 * write)
        };
        // ⚠️ A fixed register has no hole: its slot is a constant, and the
        // index it names is the description's rather than the word's. Counted
        // separately from the write ordinal, because the scratch slot is per
        // WRITE and the hole name is per OPERAND write -- an instruction with
        // both would otherwise name its second hole `dest1` while the table,
        // which lists operand writes, called it `dest0`.
        let fixed = match destination {
            Landing::Fixed { kind, index } => Some((*kind, *index)),
            Landing::Operand(_) => None,
        };
        // ⚠️ `which`, the destination's index -- not `write`, which counts
        // slots of value and runs past the end of this list the moment one
        // destination takes two.
        let operand_write = destinations[..which]
            .iter()
            .filter(|landing| matches!(landing, Landing::Operand(_)))
            .count();
        let hole = if operand_write == 0 {
            format!("{ident}_dest")
        } else {
            format!("{ident}_dest{operand_write}")
        };
        // ⚠️ Declared once, on the low limb. A wide destination commits twice
        // and names one hole both times -- the index is the register's, not
        // the slot's -- and declaring it per commit is a redefinition the
        // module will not parse.
        if fixed.is_none() && limb == 0 {
            declarations.push(format!("@AXIS_HOLE_{hole} = external dso_local global i8"));
        }
        let (v, w) = (format!("%vp{write}"), format!("%wp{write}"));
        lines.push(format!("  {v} = getelementptr {machine}, {machine}* %out, i64 {value_slot}"));
        lines.push(format!("  %valw{write} = load {machine}, {machine}* {v}"));
        lines.push(format!("  {w} = getelementptr {machine}, {machine}* %out, i64 {wrote_slot}"));
        lines.push(format!("  %wrote{write} = load {machine}, {machine}* {w}"));
        lines.push(format!("  %did{write} = icmp ne {machine} %wrote{write}, 0"));
        if width == 64 {
            lines.push(format!("  %val{write} = bitcast i64 %valw{write} to i64"));
        } else {
            lines.push(format!("  %val{write} = zext {machine} %valw{write} to i64"));
        }
        let (base, stride, zero, alias) = match fixed {
            Some((kind, index)) => {
                let class = crate::ast::register_class(kind);
                let stride = class.map_or(1, |class| u64::from(class.limbs.max(1)));
                let base = class.map_or(0, |class| {
                    u64::from(class.offset) + u64::from(class.index_offset) * stride
                });
                // The index is fixed, so there is nothing left to patch.
                lines.push(format!("  %d{write} = add i64 {index}, 0"));
                let discards = class
                    .and_then(|class| class.zero_index)
                    .is_some_and(|slot| slot == index);
                (base, stride, if discards { Some(index) } else { None }, None)
            }
            None => {
                let operand = match destination {
                    Landing::Operand(operand) => *operand,
                    Landing::Fixed { .. } => unreachable!("fixed is Some there"),
                };
                lines.push(format!(
                    "  %d{write} = load i64, i64* bitcast (i8* @AXIS_HOLE_{hole} to i64*)"
                ));
                let (base, stride, zero) = stencil_slot_shape(operand);
                (base, stride, zero, stencil_alias(operand, state_slots))
            }
        };
        lines.push(format!("  %dn{write} = mul i64 %d{write}, {stride}"));
        lines.push(format!(
            "  %di{write} = add i64 %dn{write}, {}",
            base + limb
        ));
        lines.push(format!(
            "  %dpr{write} = getelementptr i64, i64* %regs, i64 %di{write}"
        ));
        // The address is selected, not the value: one load and one store
        // either way, and the aliased index never touches the register file.
        match alias {
            Some((index, slot)) => {
                lines.push(format!("  %da{write} = icmp eq i64 %d{write}, {index}"));
                lines.push(format!(
                    "  %dap{write} = getelementptr i64, i64* %state, i64 {slot}"
                ));
                lines.push(format!(
                    "  %dp{write} = select i1 %da{write}, i64* %dap{write}, i64* %dpr{write}"
                ));
            }
            None => lines.push(format!(
                "  %dp{write} = bitcast i64* %dpr{write} to i64*"
            )),
        }
        lines.push(format!("  %old{write} = load i64, i64* %dp{write}"));
        // A guarded set decides at run time whether it wrote; a hardwired zero
        // decides that it did not. Both are the same select.
        match zero {
            Some(index) => {
                lines.push(format!("  %dz{write} = icmp ne i64 %d{write}, {index}"));
                lines.push(format!(
                    "  %commit{write} = and i1 %did{write}, %dz{write}"
                ));
                lines.push(format!(
                    "  %new{write} = select i1 %commit{write}, i64 %val{write}, i64 %old{write}"
                ));
            }
            None => lines.push(format!(
                "  %new{write} = select i1 %did{write}, i64 %val{write}, i64 %old{write}"
            )),
        }
        lines.push(format!("  store i64 %new{write}, i64* %dp{write}"));
        // ⚠️ And the rest of the register becomes zero. `ldr d1` writes the low
        // half of `v1` and the architecture says the high half is cleared --
        // which the executors do and this did not, so a translated `ldr d` left
        // whatever the high slot held and every gate agreed about the low one.
        // Under the commit condition: a write that did not fire clears nothing.
        let value_limbs = match destination {
            Landing::Operand(operand) => stencil_value_limbs(operand),
            Landing::Fixed { .. } => 1,
        };
        if last_limb && stride > value_limbs && alias.is_none() {
            let fired = if zero.is_some() {
                format!("%commit{write}")
            } else {
                format!("%did{write}")
            };
            // ⚠️ From where the VALUE ends, not from slot one. A full-width
            // write fills the register and has nothing left to clear; clearing
            // from one would wipe the high limb it had just written.
            for limb in value_limbs..stride {
                lines.push(format!(
                    "  %hi{write}_{limb} = add i64 %dn{write}, {}",
                    base + limb
                ));
                lines.push(format!(
                    "  %hp{write}_{limb} = getelementptr i64, i64* %regs, i64 %hi{write}_{limb}"
                ));
                lines.push(format!(
                    "  %hold{write}_{limb} = load i64, i64* %hp{write}_{limb}"
                ));
                lines.push(format!(
                    "  %hnew{write}_{limb} = select i1 {fired}, i64 0, i64 %hold{write}_{limb}"
                ));
                lines.push(format!(
                    "  store i64 %hnew{write}_{limb}, i64* %hp{write}_{limb}"
                ));
            }
        }
    }
    out.push_str(&format!(
        "define void @axis_stencil_{ident}() {{\nentry:\n{}\n  ret void\n}}\n",
        lines.join("\n")
    ));
}

pub fn emit_llvm_ir(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("; Generated by AXIS. Header-only LLVM IR semantics interpreter.\n");
    out.push_str("; schema: axis.semantics-llvm.v1\n");
    out.push_str(
        "; One `define i32 @axis_eval_<name>(...)` per instruction/accelerator with\n\
         ; formal_semantics, bit-identical to the golden model and axis_semantics.h.\n\n",
    );
    out.push_str(&llvm_module_preamble(document));
    out.push_str(AXIS_MEMORY_MASK_DEFINITION);
    for instruction in &document.instructions {
        let inputs: Vec<(&str, u32)> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|operand| (operand.name.as_str(), operand.width))
            .collect();
        let output_width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(32);
        // A lane-wise instruction lowers to LLVM's own vector type, so the
        // parallelism is visible to the optimizer instead of hidden in a
        // shift/mask tree. The expansion remains the definition of what the
        // operator means; this is a second implementation of it, and
        // `llvm_vs_golden.py` proves the two agree.
        let vector = emit_llvm_vector_function(
            &format!("axis_eval_{}", python_ident(&instruction.mnemonic)),
            &instruction.vector_semantics,
            &inputs,
            output_width,
        );
        match vector {
            Some(text) => out.push_str(&text),
            None => emit_llvm_function(
                &mut out,
                &format!("axis_eval_{}", python_ident(&instruction.mnemonic)),
                &instruction.formal_semantics,
                &inputs,
                output_width,
            ),
        }
    }
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    for instruction in &document.instructions {
        emit_llvm_effect_function(
            &mut out,
            instruction,
            isa_state_width(document, instruction),
            &state_names,
        );
    }
    for accelerator in &document.accelerators {
        let inputs: Vec<(&str, u32)> = accelerator
            .ports
            .iter()
            .filter(|port| matches!(port.direction.as_str(), "input" | "in"))
            .map(|port| (port.name.as_str(), port.width))
            .collect();
        let output_width = accelerator
            .ports
            .iter()
            .find(|port| matches!(port.direction.as_str(), "output" | "out"))
            .map(|port| port.width)
            .unwrap_or(32);
        emit_llvm_function(
            &mut out,
            &format!("axis_eval_{}", python_ident(&accelerator.name)),
            &accelerator.formal_semantics,
            &inputs,
            output_width,
        );
    }
    out
}

/// Emit a lane-wise function using LLVM's native vector type, or `None` when
/// the instruction is not a single vector application over its operands — in
/// which case the caller falls back to the proven scalar expansion.
///
/// Deliberately narrow: it handles one lane-parallel operator whose arguments
/// are all operands, which is the shape a SIMD instruction actually has. A
/// nested or mixed expression falls back rather than being partially
/// vectorized, because a half-native lowering is harder to reason about than
/// either extreme.
fn emit_llvm_vector_function(
    fn_name: &str,
    vector_semantics: &str,
    inputs: &[(&str, u32)],
    output_width: u32,
) -> Option<String> {
    let expr = parse_formal_semantics(vector_semantics).ok()?;
    let SemanticExpr::List(items) = &expr else {
        return None;
    };
    let (SemanticExpr::Atom(op), SemanticExpr::Atom(type_atom)) = (items.first()?, items.get(1)?)
    else {
        return None;
    };
    let shape = crate::simd::vector_type_atom(type_atom)?;
    // Native vectors for integer lanes only. A float lane would need `<N x
    // float>` and the `f`-prefixed instructions, and the operator list below is
    // integer, so a float vector falls through to the proven expansion — the
    // same fallback any unmapped operator takes.
    if shape.elem_kind != 'i' {
        return None;
    }
    let (lanes, elem) = (shape.lanes, shape.elem);
    if lanes * elem != output_width {
        return None;
    }
    // Native instruction per lane-parallel operator. `not` is unary and the
    // signed/unsigned min and max need an explicit compare, so only the
    // directly-mapped ones are taken here.
    let instruction = match op.as_str() {
        "add" => "add",
        "sub" => "sub",
        "mul" => "mul",
        "and" => "and",
        "or" => "or",
        "xor" => "xor",
        _ => return None,
    };
    let operands: Vec<&str> = items[2..]
        .iter()
        .map(|item| match item {
            SemanticExpr::Atom(name) => Some(name.as_str()),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()?;
    // Exactly two whole registers of the vector's own width. The width check is
    // what keeps the signature identical to the scalar lowering's: that one
    // types every parameter with the function's single evaluation word, the
    // widest of the operands and the result. Requiring each operand to be the
    // output width makes this function's `ty` that same word by construction,
    // so the two lowerings stay interchangeable to every harness that calls
    // them. Two operands rather than a fold also avoids having to match the
    // golden model's associativity for n-ary `sub`.
    if operands.len() != 2 {
        return None;
    }
    if !operands.iter().all(|name| {
        inputs
            .iter()
            .any(|(input, width)| input == name && *width == output_width)
    }) {
        return None;
    }
    let word = llvm_word(output_width);
    let ty = word.ty;
    let vector_ty = format!("<{lanes} x i{elem}>");
    let mut body = String::new();
    let mut counter = 0u32;
    let mut folded: Option<String> = None;
    for name in &operands {
        let cast = llvm_fresh(&mut counter);
        body.push_str(&format!(
            "  {cast} = bitcast {ty} %{} to {vector_ty}\n",
            python_ident(name)
        ));
        folded = Some(match folded {
            None => cast,
            Some(accumulator) => {
                let computed = llvm_fresh(&mut counter);
                body.push_str(&format!(
                    "  {computed} = {instruction} {vector_ty} {accumulator}, {cast}\n"
                ));
                computed
            }
        });
    }
    let result = folded?;
    let bits = llvm_fresh(&mut counter);
    body.push_str(&format!("  {bits} = bitcast {vector_ty} {result} to {ty}\n"));
    let params = inputs
        .iter()
        .map(|(name, _)| format!("{ty} %{}", python_ident(name)))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!(
        "; {lanes} x i{elem} lanes, lowered to a native vector\ndefine {ty} @{fn_name}({params}) {{\nentry:\n{body}  ret {ty} {bits}\n}}\n\n"
    ))
}

/// The widest LLVM integer AXIS lowers to. Beyond this the semantics stay in
/// the golden model and SMT, whose value domains are unbounded.
const LLVM_MAX_WIDTH: u32 = 128;

/// The architectural width an instruction's effects evaluate in: the widest of
/// its operands, its ISA's word, and each effect's own value, address, and
/// guard. `None` when the instruction has no authoritative behavior to lower.
///
/// One definition with two consumers — the emitter below and
/// `document_needs_width`, which has to register the matching helper prelude.
/// Deriving the width twice is how a call to an `@axis_sem64_*` helper that was
/// never emitted would get past a build.
pub(crate) fn effect_eval_width(instruction: &crate::ast::Instruction, state_width: u32) -> Option<u32> {
    use crate::effects::Loc;
    if !crate::effects::behavior_is_authoritative(instruction) {
        return None;
    }
    let behavior = instruction.behavior.as_ref()?;
    // Checking only the operands would silently emit a 64-bit `sext` as i32 —
    // an AArch64 `B` sign-extends its 26-bit displacement to the pc width while
    // its only operand is a 26-bit immediate.
    let effect_width = |effect: &crate::effects::Effect| {
        let mut widest = effect
            .value
            .width
            .max(effect.value.load_address_width.unwrap_or(0));
        if let Loc::Mem { addr, width, .. } = &effect.loc {
            widest = widest.max(addr.width).max(*width);
        }
        if let Some(guard) = &effect.guard {
            widest = widest.max(guard.width);
        }
        widest
    };
    Some(
        instruction
            .operands
            .iter()
            .map(|operand| operand.width)
            .chain(std::iter::once(state_width))
            .chain(behavior.effects.iter().map(effect_width))
            .max()
            .unwrap_or(32),
    )
}

/// The ISA word an instruction's effects evaluate against.
fn isa_state_width(document: &Document, instruction: &crate::ast::Instruction) -> u32 {
    document
        .isas
        .iter()
        .find(|isa| isa.name == instruction.isa)
        .map(|isa| isa.word_bits)
        .unwrap_or(32)
}

/// Widest evaluation width the effect ABI lowers. A pc, an address, and a
/// register all fit in 64 bits; a 128-bit effect surface would need a memory
/// model that does not exist, so those stay withheld rather than approximated.
const LLVM_EFFECT_MAX_WIDTH: u32 = 64;

/// Which wider preludes a module needs, in ascending order. A document with
/// only 32-bit semantics needs none, so its module is unchanged.
pub(crate) fn wide_semantics_widths(document: &Document) -> Vec<u32> {
    [64u32, 128]
        .into_iter()
        .filter(|width| document_needs_width(document, *width))
        .collect()
}

/// Whether any entry evaluates at exactly `bucket` — the width its lowering
/// would round up to.
fn document_needs_width(document: &Document, bucket: u32) -> bool {
    let wide = |inputs: &[u32], output: u32| {
        let widest = inputs.iter().copied().max().unwrap_or(0).max(output);
        widest > 32 && widest <= LLVM_MAX_WIDTH && llvm_word(widest).bits == bucket
    };
    document.instructions.iter().any(|instruction| {
        // An effect function lowers against the same prelude as a pure one, so
        // its width has to register here too or it would call helpers the
        // module never defines.
        effect_eval_width(instruction, isa_state_width(document, instruction))
            .is_some_and(|widest| {
                widest > 32 && widest <= LLVM_EFFECT_MAX_WIDTH && llvm_word(widest).bits == bucket
            })
    }) || document.instructions.iter().any(|instruction| {
        !instruction.formal_semantics.trim().is_empty()
            && wide(
                &instruction
                    .operands
                    .iter()
                    .filter(|operand| operand.input)
                    .map(|operand| operand.width)
                    .collect::<Vec<_>>(),
                instruction
                    .operands
                    .iter()
                    .find(|operand| operand.output)
                    .map(|operand| operand.width)
                    .unwrap_or(32),
            )
    }) || document.accelerators.iter().any(|accelerator| {
        !accelerator.formal_semantics.trim().is_empty()
            && wide(
                &accelerator
                    .ports
                    .iter()
                    .filter(|port| matches!(port.direction.as_str(), "input" | "in"))
                    .map(|port| port.width)
                    .collect::<Vec<_>>(),
                accelerator
                    .ports
                    .iter()
                    .find(|port| matches!(port.direction.as_str(), "output" | "out"))
                    .map(|port| port.width)
                    .unwrap_or(32),
            )
    })
}

/// Render the helper prelude at one evaluation width.
pub(crate) fn render_semantics_helpers(word: Word) -> String {
    let int_min = match word.bits {
        128 => i128::MIN.to_string(),
        64 => i64::MIN.to_string(),
        _ => i32::MIN.to_string(),
    };
    LLVM_SEMANTICS_TEMPLATE
        .replace("{ty}", word.ty)
        .replace("{prefix}", word.prefix)
        .replace("{wm1}", &(word.bits - 1).to_string())
        .replace("{w}", &word.bits.to_string())
        .replace("{imin}", &int_min)
}

/// The LLVM integer type an expression evaluates in, plus the matching helper
/// prefix. Widths up to 32 lower in `i32` against the `axis_sem_*` prelude;
/// wider ones lower in `i64` against its `axis_sem64_*` twin.
#[derive(Clone, Copy)]
pub(crate) struct Word {
    pub(crate) bits: u32,
    pub(crate) ty: &'static str,
    pub(crate) prefix: &'static str,
}

pub(crate) fn llvm_word(width: u32) -> Word {
    if width > 64 {
        Word { bits: 128, ty: "i128", prefix: "axis_sem128_" }
    } else if width > 32 {
        Word { bits: 64, ty: "i64", prefix: "axis_sem64_" }
    } else {
        Word { bits: 32, ty: "i32", prefix: "axis_sem_" }
    }
}

fn emit_llvm_function(
    out: &mut String,
    fn_name: &str,
    formal_semantics: &str,
    inputs: &[(&str, u32)],
    output_width: u32,
) {
    if formal_semantics.trim().is_empty() {
        out.push_str(&format!("; {fn_name}: no formal_semantics declared\n\n"));
        return;
    }
    // One evaluation type for the whole function: the widest operand or
    // result. A 32-bit instruction is unchanged; a 64-bit one lowers in i64
    // against the widened prelude instead of being skipped.
    let widest = inputs
        .iter()
        .map(|(_, width)| *width)
        .max()
        .unwrap_or(0)
        .max(output_width);
    if widest > LLVM_MAX_WIDTH {
        out.push_str(&format!(
            "; {fn_name}: widths beyond {LLVM_MAX_WIDTH} bits are not supported yet\n\n"
        ));
        return;
    }
    // LLVM cannot perform directed rounding. Its constrained intrinsics take a
    // rounding mode as metadata, but that metadata *constrains the optimizer* --
    // it says the mode is not known to be round-to-nearest -- and the arithmetic
    // still rounds by whatever the hardware floating-point environment holds.
    // Measured rather than assumed: a four-way switch over
    // `llvm.experimental.constrained.fadd.f64` returns the identical value for
    // all four modes, including under `-ffp-model=strict`, while C's
    // `fesetround` returns three distinct ones for the same operands. Emitted IR
    // has no portable way to set that environment, so the operator is declined
    // rather than lowered to something that silently rounds to nearest.
    //
    // That measurement is a premise about the host LLVM, so it is a gate rather
    // than a memory: `tools/fp_rounding_check.py` adds the same two numbers
    // under `round.downward` and `round.upward` every run and requires the same
    // answer back. When a newer LLVM stops discarding the mode the gate fails,
    // and the failure says that this decline can be lifted.
    // See docs/simd_fp_design.md section 8.3.
    if crate::emit::semantics::uses_fp_exceptions(formal_semantics) {
        out.push_str(&format!(
            "; {fn_name}: the exceptions an operation raises are read from the\n\
             ; floating-point environment, which emitted LLVM IR cannot reach\n\n"
        ));
        return;
    }
    if formal_semantics.contains("_rm ") {
        out.push_str(&format!(
            "; {fn_name}: an explicit rounding mode needs the floating-point\n\
             ; environment, which emitted LLVM IR cannot set; see\n\
             ; docs/simd_fp_design.md section 8.3\n\n"
        ));
        return;
    }
    let word = llvm_word(widest);
    let ty = word.ty;
    let Ok(expr) = parse_formal_semantics(formal_semantics) else {
        out.push_str(&format!("; {fn_name}: unparseable formal_semantics\n\n"));
        return;
    };
    let Ok(sem) = lower(&expr, output_width) else {
        out.push_str(&format!(
            "; {fn_name}: semantics not expressible in LLVM IR yet\n\n"
        ));
        return;
    };
    let params = inputs
        .iter()
        .map(|(name, _)| format!("{ty} %{}", python_ident(name)))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = String::new();
    let mut counter = 0u32;
    let result = llvm_lower(&sem, word, &mut body, &mut counter);
    let ret = llvm_fresh(&mut counter);
    body.push_str(&format!(
        "  {ret} = call {ty} @{}mask({ty} {result}, {ty} {output_width})\n",
        word.prefix
    ));
    out.push_str(&format!(
        "define {ty} @{fn_name}({params}) {{\nentry:\n{body}  ret {ty} {ret}\n}}\n\n"
    ));
}

/// Emit `define void @axis_eff_<name>(i8* %mem, i32 %pc, i32* %out, i32 %<input>…)`
/// for an instruction whose behavior the pure path cannot hold (E5).
///
/// Pointers are typed rather than opaque (`ptr`) because that is what both
/// consumers accept: clang takes either, while llvmlite's bundled LLVM — the
/// in-process JIT in `tools/jit_llvm.py` — parses only typed pointers. Newer
/// LLVM deprecates the syntax, so this is the compatibility choice to revisit
/// when the JIT's LLVM moves.
///
/// The contract mirrors the proven C effect functions, minus their dependence
/// on the lift structs, so the module stays self-contained:
///
/// * `%mem` is a flat little-endian byte buffer; loads and stores lower to
///   native LLVM `load`/`store` against it, which is the point of E5 — memory
///   effects become optimizer-visible instead of opaque calls.
/// * `%out` is an `i32` array: `[0]` the written value, `[1]` whether a
///   register was written, `[2]` the next pc, `[3]` the trap id (0 = none,
///   otherwise the 1-based index into `effects::TRAP_CAUSES`).
/// * `%pc` is the current pc; `out[2]` starts at the `pc + 4` fall-through and
///   is overwritten only by a `setpc`, matching the executors' rule.
///
/// A trap stores its id and returns immediately, aborting the remaining
/// effects exactly as the C and Python executors do. Effects the 32-bit
/// surface does not cover (named state, fixed registers, barriers, atomic
/// groups, or any operand wider than 32 bits) are withheld with a comment
/// rather than approximated.
/// Why LLVM IR cannot express this instruction's behavior, or `None`.
///
/// The single place that decides. `emit_llvm_effect_function` withholds a
/// function for these reasons, and a lifted region has to refuse exactly the
/// same set: lowering one of them anyway does not produce wrong IR, it panics
/// in `llvm_convert` with "not a conversion", which is a much worse way to
/// learn that RISC-V's dynamic-rounding forms take their mode from `fcsr`.
pub(crate) fn llvm_effect_refusal(
    instruction: &crate::ast::Instruction,
    state_width: u32,
    state_names: &[String],
) -> Option<String> {
    use crate::effects::Loc;
    let Some(widest) = effect_eval_width(instruction, state_width) else {
        return Some("no authoritative behavior".to_string());
    };
    let behavior = instruction.behavior.as_ref()?;
    let limb_split = widest > LLVM_EFFECT_MAX_WIDTH
        && behavior_is_whole_limbs(instruction, behavior, llvm_word(LLVM_EFFECT_MAX_WIDTH));
    if widest > LLVM_EFFECT_MAX_WIDTH && !limb_split {
        return Some(format!(
            "widths beyond {LLVM_EFFECT_MAX_WIDTH} bits are not supported yet"
        ));
    }
    if behavior.effects.iter().any(|effect| {
        let value = crate::effects::render_semantic_expr(&effect.value.expr);
        value.contains("_rm ")
            || crate::emit::semantics::uses_fp_exceptions(&value)
            || effect.guard.as_ref().is_some_and(|guard| {
                crate::effects::render_semantic_expr(&guard.expr).contains("_rm ")
            })
    }) {
        return Some(
            "an explicit rounding mode needs the floating-point environment".to_string(),
        );
    }
    // ⚠️ A group the fusion TAKES is not a refusal. An `atomic-group` says these
    // effects are one architectural transaction, and a single `cmpxchg` is one
    // transaction -- the group is the reason to fuse, not a reason to decline.
    // `emit_llvm_effect_function` already tried the fusion before asking this;
    // this function asked first and so refused every `CASP`, whose four effects
    // are exactly one paired compare-and-swap.
    let fusable = {
        let word = llvm_word(if limb_split { LLVM_EFFECT_MAX_WIDTH } else { widest });
        let atomic = behavior.effects.iter().any(|effect| {
            effect.value.load_atomic || matches!(effect.loc, Loc::Mem { atomic: true, .. })
        });
        atomic && llvm_atomic_pair(instruction, behavior, word, None, &mut 0).is_some()
    };
    if !fusable
        && behavior.effects.iter().any(|effect| {
            effect.atomic_group != 0
                || matches!(&effect.loc, Loc::Barrier { kind, .. } if fence_ordering(kind).is_none())
        })
    {
        return Some("an atomic group, or a barrier LLVM cannot order".to_string());
    }
    if let Some(reason) = single_write_abi_cannot_express(instruction) {
        return Some(reason.to_string());
    }
    // ⚠️ The last question is asked by *doing it*, not by predicting it.
    // Everything above names a shape known to be unlowerable; below them sits a
    // long tail that `llvm_effect_body` only discovers when it tries -- an
    // operator with no LLVM form, a value reading state this instruction has no
    // parameter for. `emit_llvm_effect_function` finds out the same way and
    // writes a comment instead of a function.
    //
    // Predicting that tail with a second predicate is how the two drifted:
    // this function called RISC-V's `FLS` liftable, the emitter then declined
    // it, and the region lifter failed at lowering with "a value is not
    // lowerable" -- which the per-instruction sweep dropped in silence until it
    // started counting what it accepted but could not lift. Running the real
    // lowering and throwing the text away cannot drift from it.
    let word = llvm_word(if limb_split { LLVM_EFFECT_MAX_WIDTH } else { widest });
    let mut renames: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for name in state_names {
        if behavior_mentions_state(behavior, name) {
            renames.insert(name.clone(), format!("axis.probe.{name}"));
        }
    }
    let mut counter = 0u32;
    if fusable {
        return None;                    // the fusion expresses the whole thing
    }
    for (write_index, effect) in behavior.effects.iter().enumerate() {
        if llvm_effect_body(
            instruction, effect, word, write_index, state_names, &mut renames,
            &mut counter,
        )
        .is_none()
        {
            return Some(
                "an effect is not expressible in LLVM IR: an unsupported \
                 operator, or a value reading state it has no parameter for"
                    .to_string(),
            );
        }
    }
    None
}

fn emit_llvm_effect_function(
    out: &mut String,
    instruction: &crate::ast::Instruction,
    state_width: u32,
    state_names: &[String],
) {
    use crate::effects::Loc;
    let fn_name = format!("axis_eff_{}", python_ident(&instruction.mnemonic));
    // ⚠️ An instruction with nothing to lower is NAMED, not passed over. The
    // pure path's note says "no formal_semantics declared" about every
    // effectful instruction, so it cannot distinguish one this path also
    // dropped -- and 26 instructions across nine corpora left the file with no
    // function and no comment at all. What is said depends on which silence it
    // is, the same three the lifter distinguishes: a routine performs it, it is
    // declared unsupplied, or nothing has been said yet.
    let nothing_to_lower = |out: &mut String| {
        let answer = instruction.implementation.trim();
        let reason = if answer == crate::ast::UNSUPPLIED {
            "declared unsupplied: nothing here performs it".to_string()
        } else if !answer.is_empty() {
            format!("performed by the routine `{answer}`, which only an executor can call")
        } else {
            "no semantics and no behavior to lower".to_string()
        };
        out.push_str(&format!("; {fn_name}: {reason}\n\n"));
    };
    let Some(widest) = effect_eval_width(instruction, state_width) else {
        if instruction.behavior.is_none()
            && instruction.formal_semantics.trim().is_empty()
        {
            nothing_to_lower(out);
        }
        return;
    };
    let Some(behavior) = instruction.behavior.as_ref() else {
        if instruction.formal_semantics.trim().is_empty() {
            nothing_to_lower(out);
        }
        return;
    };
    // A width past a slot is not automatically past this ABI. If every effect
    // moves whole limbs -- a vector register loaded or stored as a unit -- the
    // function is emitted at the slot width and the access is split, which is
    // the same shape `ldp`/`stp` already have and the same shape the register
    // file has. Anything else keeps the refusal.
    let limb_split = widest > LLVM_EFFECT_MAX_WIDTH
        && behavior_is_whole_limbs(instruction, behavior, llvm_word(LLVM_EFFECT_MAX_WIDTH));
    if widest > LLVM_EFFECT_MAX_WIDTH && !limb_split {
        out.push_str(&format!(
            "; {fn_name}: widths beyond {LLVM_EFFECT_MAX_WIDTH} bits are not supported yet\n\n"
        ));
        return;
    }
    let widest = if limb_split { LLVM_EFFECT_MAX_WIDTH } else { widest };
    // Directed rounding is declined here for the same reason as on the pure
    // path above: LLVM's constrained intrinsics take the mode as metadata that
    // constrains the optimizer, and the arithmetic still rounds by whatever the
    // hardware environment holds, which emitted IR cannot set.
    //
    // The pure path's guard reads `formal_semantics`, so an instruction that
    // states its rounding in a `behavior` slipped past it and reached a
    // lowering that panicked with "declined before lowering". RISC-V's `DYN`
    // forms are exactly that shape -- they take the mode from `fcsr.frm`, which
    // only a behavior can read.
    if behavior.effects.iter().any(|effect| {
        let value = crate::effects::render_semantic_expr(&effect.value.expr);
        value.contains("_rm ")
            || crate::emit::semantics::uses_fp_exceptions(&value)
            || effect.guard.as_ref().is_some_and(|guard| {
                crate::effects::render_semantic_expr(&guard.expr).contains("_rm ")
            })
    }) {
        out.push_str(&format!(
            "; {fn_name}: an explicit rounding mode needs the floating-point\n\
             ; environment, which emitted LLVM IR cannot set; see\n\
             ; docs/simd_fp_design.md section 8.3\n\n"
        ));
        return;
    }
    let word = llvm_word(widest);
    let ty = word.ty;
    // An atomic group of exactly two effects with the read-modify-write shape is
    // *precisely* what a single `atomicrmw` or `cmpxchg` expresses, so the group
    // enables the fusion rather than blocking it. The rule below predates the
    // fused path: AArch64's atomics are written as two effects marked atomic
    // without a group and so fused, while RISC-V's are written inside a group —
    // the more explicit spelling of the same thing — and were withheld for it.
    {
        // The prologue is generated first so temps are numbered in the order
        // they appear, the same as the non-fused path.
        let mut probe = 0u32;
        let prologue = effect_prologue(word, &mut probe);
        // ⚠️ Only when the fusion is the WHOLE instruction. A partial one --
        // `LDXP`, whose two loads fuse and whose three monitor writes do not --
        // has to go through the main path below, which knows how to write
        // architectural state. Returning here regardless emitted the loads and
        // silently dropped the monitor, which is a lifted `ldxp` that leaves no
        // trace a `stxp` could test.
        let whole = llvm_atomic_pair(instruction, behavior, word, None, &mut probe)
            .filter(|fused| fused.consumed >= behavior.effects.len());
        if let Some(fused) = whole {
            let mut body = prologue;
            body.push_str(&fused.body);
            let ty = word.ty;
            for (slot, (_dest, value)) in fused.writes.iter().enumerate() {
                body.push_str(&format!(
                    "  store {ty} {value}, {ty}* %axis.value{slot}\n  store {ty} 1, {ty}* %axis.wrote{slot}\n"
                ));
            }
            out.push_str(&format!(
                "define void @{fn_name}({}) {{\nentry:\n{body}  ret void\n}}\n\n",
                effect_params(instruction, ty)
            ));
            return;
        }
    }
    // A group the fusion takes -- whole or in part -- is expressed, not refused:
    // the group says these effects are one transaction, and that is the reason
    // to fuse them. `llvm_effect_refusal` was taught the same thing.
    let fusable = {
        let mut probe = 0u32;
        llvm_atomic_pair(instruction, behavior, word, None, &mut probe).is_some()
    };
    if !fusable
        && behavior.effects.iter().any(|effect| {
            effect.atomic_group != 0
                || matches!(&effect.loc, Loc::Barrier { kind, .. } if fence_ordering(kind).is_none())
        })
    {
        out.push_str(&format!(
            "; {fn_name}: an atomic group, or a barrier with no ordering LLVM can\n\
             ; express (an instruction or speculation barrier)\n\n"
        ));
        return;
    }

    // Operand name -> the SSA temp holding its current value, so an effect that
    // writes a register is visible to the ones after it. Architectural state
    // joins the same map: it is loaded once into a temp at entry, and a write
    // rebinds it, which is what the executors' mutable state map does.
    let mut renames: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    if let Some(reason) = single_write_abi_cannot_express(instruction) {
        out.push_str(&format!("; {fn_name}: {reason}\n\n"));
        return;
    }

    let mut body = String::new();
    let mut counter = 0u32;
    for (slot, name) in state_names.iter().enumerate() {
        if !behavior_mentions_state(behavior, name) {
            continue;
        }
        let pointer = llvm_fresh(&mut counter);
        let loaded = llvm_fresh(&mut counter);
        body.push_str(&format!(
            "  {pointer} = getelementptr {ty}, {ty}* %state, i32 {slot}\n  {loaded} = load {ty}, {ty}* {pointer}\n"
        ));
        renames.insert(name.clone(), loaded.trim_start_matches('%').to_string());
    }
    body.push_str(&effect_prologue(word, &mut counter));

    // An atomic read-modify-write is one LLVM instruction or nothing: see
    // `llvm_atomic_pair` for why splitting it would be unobservably wrong.
    let atomic = behavior
        .effects
        .iter()
        .any(|effect| effect.value.load_atomic || matches!(effect.loc, Loc::Mem { atomic: true, .. }));
    let fused = if atomic {
        llvm_atomic_pair(instruction, behavior, word, None, &mut counter)
    } else {
        None
    };
    // ⚠️ A fusion consumes a PREFIX of the effects, not necessarily all of them.
    // `CASP` is the whole instruction; `LDXP` is the two loads, and the three
    // effects after them are the exclusive monitor -- ordinary architectural
    // state, which this function already knows how to write. `consumed` has
    // said which since the struct was introduced, and nothing read it, so a
    // partial fusion had no way to be expressed and paired loads were refused.
    let mut write_index = 0usize;
    let mut skip = 0usize;
    if let Some(fused) = fused {
        body.push_str(&fused.body);
        for (dest, value) in fused.writes.iter() {
            body.push_str(&format!(
                "  store {ty} {value}, {ty}* %axis.value{write_index}\n  store {ty} 1, {ty}* %axis.wrote{write_index}\n"
            ));
            write_index += 1;
            // Later effects read what this one wrote, the same as the
            // unfused path.
            renames.insert(dest.clone(), value.trim_start_matches('%').to_string());
        }
        skip = fused.consumed;
        if skip >= behavior.effects.len() {
            out.push_str(&format!(
                "define void @{fn_name}({}) {{\nentry:\n{body}  ret void\n}}\n\n",
                effect_params(instruction, ty)
            ));
            return;
        }
    }

    for effect in behavior.effects.iter().skip(skip) {
        let Some(effect_body) = llvm_effect_body(
            instruction,
            effect,
            word,
            write_index,
            state_names,
            &mut renames,
            &mut counter,
        ) else {
            // ⚠️ Name the cause when it is known. A behavior that reads a
            // register the description names itself -- `getreg reg 3` rather
            // than an operand -- cannot be lowered here for a reason specific
            // enough to say: this ABI passes memory, the pc, the result and
            // architectural state, and no register file. The generic message
            // said "an unsupported operator, or a value that reads
            // architectural state", which is neither of those things.
            let reason = if !crate::effects::behavior_register_reads(instruction).is_empty() {
                "the behavior reads a register it names itself, and this ABI \
                 passes no register file"
                    .to_string()
            } else {
                "an effect is not expressible in LLVM IR yet — an unsupported \
                 operator, or a value that reads architectural state"
                    .to_string()
            };
            out.push_str(&format!("; {fn_name}: {reason}\n\n"));
            return;
        };
        if matches!(effect.loc, Loc::Reg(_) | Loc::FixedReg { .. }) {
            // A 128-bit destination reports one limb per slot, so it consumes
            // two: the write slots are register slots, and that is how many the
            // register occupies.
            write_index += effect_limbs(instruction, effect, word);
        }
        match &effect.guard {
            None => body.push_str(&effect_body),
            Some(guard) => {
                let Some(condition) = llvm_guard(
                    &guard.expr,
                    guard.width,
                    word,
                    &effect_symbols(instruction, state_names),
                    &renames,
                    &mut body,
                    &mut counter,
                )
                else {
                    out.push_str(&format!(
                        "; {fn_name}: a guard is not expressible in LLVM IR yet\n\n"
                    ));
                    return;
                };
                let taken = format!("guard{counter}.taken");
                let done = format!("guard{counter}.done");
                counter += 1;
                body.push_str(&format!(
                    "  br i1 {condition}, label %{taken}, label %{done}\n{taken}:\n{effect_body}  br label %{done}\n{done}:\n"
                ));
            }
        }
    }

    out.push_str(&format!(
        "define void @{fn_name}({}) {{\nentry:\n{body}  ret void\n}}\n\n",
        effect_params(instruction, ty)
    ));
}

/// `i8* %mem, iW %pc, iW* %out, iW* %state` plus one parameter per input
/// operand.
///
/// `%state` is present on every effect function, not only the ones that touch
/// architectural state, so a caller has one calling convention to implement
/// rather than a signature that depends on the instruction.
/// The parameter name carrying limb `limb` of an input operand. Limb 0 keeps
/// the operand's own name so every existing signature is unchanged; the rest
/// are dotted, which an operand identifier cannot be.
fn limb_param(name: &str, limb: usize) -> String {
    if limb == 0 {
        python_ident(name)
    } else {
        format!("{}.limb{limb}", python_ident(name))
    }
}

fn effect_params(instruction: &crate::ast::Instruction, ty: &str) -> String {
    let bits: u32 = ty.trim_start_matches('i').parse().unwrap_or(64);
    let params = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        // An operand wider than a slot arrives as limbs, low first -- the same
        // decomposition the register file uses, so a caller passes what it
        // holds rather than a number it has no type for.
        .flat_map(|operand| {
            let limbs = if operand.width > bits {
                operand.width.div_ceil(bits) as usize
            } else {
                1
            };
            (0..limbs)
                .map(|limb| format!("{ty} %{}", limb_param(&operand.name, limb)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    if params.is_empty() {
        format!("i8* %mem, {ty} %pc, {ty}* %out, {ty}* %state")
    } else {
        format!(
            "i8* %mem, {ty} %pc, {ty}* %out, {ty}* %state, {}",
            params.join(", ")
        )
    }
}

/// AArch64's ISA-specific operators, ported from the proven C helpers in
/// `emit::lift`. They stay out of the portable `Sem` IR on purpose — that IR is
/// the shared semantic core five backends agree on, and a flag nibble or a
/// shifted-register form is not shared semantics — so this mirrors what the C
/// and Rust executors already do: pattern-match the operator and call a helper.
///
/// Emitted only when a document uses them, so every other module is unchanged.
/// Each was checked against the golden model standalone before being wired in —
/// 36000 comparisons across the ten — which is a much shorter loop than finding
/// a hand-written IR bug through the full differential gate.
const A64_HELPERS: &str = "define internal i64 @axis_a64_logic_nzcv(i64 %value, i64 %w) {\nentry:\n  %m = call i64 @axis_sem64_mask(i64 %value, i64 %w)\n  %top = sub i64 %w, 1\n  %sh = lshr i64 %m, %top\n  %nbit = and i64 %sh, 1\n  %n = shl i64 %nbit, 3\n  %iszero = icmp eq i64 %m, 0\n  %z = select i1 %iszero, i64 4, i64 0\n  %r = or i64 %n, %z\n  ret i64 %r\n}\n\ndefine internal i64 @axis_a64_nzcv_bits(i64 %r, i64 %c, i64 %v, i64 %w) {\nentry:\n  %top = sub i64 %w, 1\n  %sh = lshr i64 %r, %top\n  %nbit = and i64 %sh, 1\n  %n = shl i64 %nbit, 3\n  %iszero = icmp eq i64 %r, 0\n  %z = select i1 %iszero, i64 4, i64 0\n  %cb = shl i64 %c, 1\n  %nz = or i64 %n, %z\n  %ncz = or i64 %nz, %cb\n  %out = or i64 %ncz, %v\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_add_nzcv(i64 %a0, i64 %b0, i64 %w) {\nentry:\n  %a = call i64 @axis_sem64_mask(i64 %a0, i64 %w)\n  %b = call i64 @axis_sem64_mask(i64 %b0, i64 %w)\n  %sum = add i64 %a, %b\n  %r = call i64 @axis_sem64_mask(i64 %sum, i64 %w)\n  ; carry: the sum leaves the width. At 64 bits that is a wrap, below it a\n  ; value above the mask.\n  %is64 = icmp uge i64 %w, 64\n  %wrapped = icmp ult i64 %r, %a\n  %maskv = call i64 @axis_sem64_mask(i64 -1, i64 %w)\n  %above = icmp ugt i64 %sum, %maskv\n  %carrybit = select i1 %is64, i1 %wrapped, i1 %above\n  %c = zext i1 %carrybit to i64\n  ; overflow: operands agree in sign and the result disagrees\n  %axb = xor i64 %a, %b\n  %same = xor i64 %axb, -1\n  %axr = xor i64 %a, %r\n  %both = and i64 %same, %axr\n  %top = sub i64 %w, 1\n  %vsh = lshr i64 %both, %top\n  %v = and i64 %vsh, 1\n  %out = call i64 @axis_a64_nzcv_bits(i64 %r, i64 %c, i64 %v, i64 %w)\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_sub_nzcv(i64 %a0, i64 %b0, i64 %w) {\nentry:\n  %a = call i64 @axis_sem64_mask(i64 %a0, i64 %w)\n  %b = call i64 @axis_sem64_mask(i64 %b0, i64 %w)\n  %diff = sub i64 %a, %b\n  %r = call i64 @axis_sem64_mask(i64 %diff, i64 %w)\n  %nb = icmp uge i64 %a, %b\n  %c = zext i1 %nb to i64\n  %axb = xor i64 %a, %b\n  %axr = xor i64 %a, %r\n  %both = and i64 %axb, %axr\n  %top = sub i64 %w, 1\n  %vsh = lshr i64 %both, %top\n  %v = and i64 %vsh, 1\n  %out = call i64 @axis_a64_nzcv_bits(i64 %r, i64 %c, i64 %v, i64 %w)\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_cond_holds(i64 %nzcv, i64 %cond) {\nentry:\n  %nb = and i64 %nzcv, 8\n  %n = icmp ne i64 %nb, 0\n  %zb = and i64 %nzcv, 4\n  %z = icmp ne i64 %zb, 0\n  %cb = and i64 %nzcv, 2\n  %c = icmp ne i64 %cb, 0\n  %vb = and i64 %nzcv, 1\n  %v = icmp ne i64 %vb, 0\n  %nz = xor i1 %z, true\n  %nc = xor i1 %c, true\n  %nn = xor i1 %n, true\n  %nv = xor i1 %v, true\n  %nev = icmp eq i1 %n, %v\n  %nnev = xor i1 %nev, true\n  %cnz = and i1 %c, %nz\n  %ncorz = or i1 %nc, %z\n  %nzandnev = and i1 %nz, %nev\n  %zornnev = or i1 %z, %nnev\n  %sel = and i64 %cond, 15\n  switch i64 %sel, label %always [ i64 0, label %c0\n    i64 1, label %c1\n    i64 2, label %c2\n    i64 3, label %c3\n    i64 4, label %c4\n    i64 5, label %c5\n    i64 6, label %c6\n    i64 7, label %c7\n    i64 8, label %c8\n    i64 9, label %c9\n    i64 10, label %c10\n    i64 11, label %c11\n    i64 12, label %c12\n    i64 13, label %c13 ]\nc0:\n  %r0 = zext i1 %z to i64\n  ret i64 %r0\nc1:\n  %r1 = zext i1 %nz to i64\n  ret i64 %r1\nc2:\n  %r2 = zext i1 %c to i64\n  ret i64 %r2\nc3:\n  %r3 = zext i1 %nc to i64\n  ret i64 %r3\nc4:\n  %r4 = zext i1 %n to i64\n  ret i64 %r4\nc5:\n  %r5 = zext i1 %nn to i64\n  ret i64 %r5\nc6:\n  %r6 = zext i1 %v to i64\n  ret i64 %r6\nc7:\n  %r7 = zext i1 %nv to i64\n  ret i64 %r7\nc8:\n  %r8 = zext i1 %cnz to i64\n  ret i64 %r8\nc9:\n  %r9 = zext i1 %ncorz to i64\n  ret i64 %r9\nc10:\n  %r10 = zext i1 %nev to i64\n  ret i64 %r10\nc11:\n  %r11 = zext i1 %nnev to i64\n  ret i64 %r11\nc12:\n  %r12 = zext i1 %nzandnev to i64\n  ret i64 %r12\nc13:\n  %r13 = zext i1 %zornnev to i64\n  ret i64 %r13\nalways:\n  ret i64 1\n}\n\ndefine internal i64 @axis_a64_shift_reg(i64 %value0, i64 %shift, i64 %amount0, i64 %w) {\nentry:\n  %value = call i64 @axis_sem64_mask(i64 %value0, i64 %w)\n  %limit = sub i64 %w, 1\n  %amount = and i64 %amount0, %limit\n  %kind = and i64 %shift, 3\n  switch i64 %kind, label %ror [ i64 0, label %lsl\n    i64 1, label %lsr\n    i64 2, label %asr ]\nlsl:\n  %shifted = shl i64 %value, %amount\n  %lslr = call i64 @axis_sem64_mask(i64 %shifted, i64 %w)\n  ret i64 %lslr\nlsr:\n  %lsrr = lshr i64 %value, %amount\n  ret i64 %lsrr\nasr:\n  %signed = call i64 @axis_sem64_signext(i64 %value, i64 %w)\n  %arith = ashr i64 %signed, %amount\n  %asrr = call i64 @axis_sem64_mask(i64 %arith, i64 %w)\n  ret i64 %asrr\nror:\n  %zero = icmp eq i64 %amount, 0\n  br i1 %zero, label %ror_none, label %ror_some\nror_none:\n  ret i64 %value\nror_some:\n  %low = lshr i64 %value, %amount\n  %back = sub i64 %w, %amount\n  %high = shl i64 %value, %back\n  %joined = or i64 %low, %high\n  %rorr = call i64 @axis_sem64_mask(i64 %joined, i64 %w)\n  ret i64 %rorr\n}\n\ndefine internal i64 @axis_a64_extend_reg(i64 %value, i64 %option, i64 %amount, i64 %w) {\nentry:\n  %kind = and i64 %option, 3\n  %source = shl i64 8, %kind\n  %masked = call i64 @axis_sem64_mask(i64 %value, i64 %source)\n  %signedbit = and i64 %option, 4\n  %issigned = icmp ne i64 %signedbit, 0\n  %narrow = icmp ult i64 %source, 64\n  %extendit = and i1 %issigned, %narrow\n  %sext = call i64 @axis_sem64_signext(i64 %masked, i64 %source)\n  %extended = select i1 %extendit, i64 %sext, i64 %masked\n  %by = and i64 %amount, 7\n  %shifted = shl i64 %extended, %by\n  %out = call i64 @axis_sem64_mask(i64 %shifted, i64 %w)\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_adc_nzcv(i64 %a0, i64 %b0, i64 %carry0, i64 %w) {\nentry:\n  %a = call i64 @axis_sem64_mask(i64 %a0, i64 %w)\n  %b = call i64 @axis_sem64_mask(i64 %b0, i64 %w)\n  %carry = and i64 %carry0, 1\n  %sum = add i64 %a, %b\n  %total = add i64 %sum, %carry\n  %r = call i64 @axis_sem64_mask(i64 %total, i64 %w)\n  %is64 = icmp uge i64 %w, 64\n  %wrap1 = icmp ult i64 %sum, %a\n  %wrap2 = icmp ult i64 %total, %sum\n  %wrapped = or i1 %wrap1, %wrap2\n  %maskv = call i64 @axis_sem64_mask(i64 -1, i64 %w)\n  %above = icmp ugt i64 %total, %maskv\n  %carrybit = select i1 %is64, i1 %wrapped, i1 %above\n  %c = zext i1 %carrybit to i64\n  %axb = xor i64 %a, %b\n  %same = xor i64 %axb, -1\n  %axr = xor i64 %a, %r\n  %both = and i64 %same, %axr\n  %top = sub i64 %w, 1\n  %vsh = lshr i64 %both, %top\n  %v = and i64 %vsh, 1\n  %out = call i64 @axis_a64_nzcv_bits(i64 %r, i64 %c, i64 %v, i64 %w)\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_sbc_nzcv(i64 %a0, i64 %b0, i64 %carry0, i64 %w) {\nentry:\n  %a = call i64 @axis_sem64_mask(i64 %a0, i64 %w)\n  %b = call i64 @axis_sem64_mask(i64 %b0, i64 %w)\n  %carry = and i64 %carry0, 1\n  %borrow = sub i64 1, %carry\n  %difference = sub i64 %a, %b\n  %total = sub i64 %difference, %borrow\n  %r = call i64 @axis_sem64_mask(i64 %total, i64 %w)\n  %lt = icmp ult i64 %a, %b\n  %lt2 = icmp ult i64 %difference, %borrow\n  %borrowed = or i1 %lt, %lt2\n  %nb = xor i1 %borrowed, true\n  %c = zext i1 %nb to i64\n  %axb = xor i64 %a, %b\n  %axr = xor i64 %a, %r\n  %both = and i64 %axb, %axr\n  %top = sub i64 %w, 1\n  %vsh = lshr i64 %both, %top\n  %v = and i64 %vsh, 1\n  %out = call i64 @axis_a64_nzcv_bits(i64 %r, i64 %c, i64 %v, i64 %w)\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_umulh(i64 %a, i64 %b) {\nentry:\n  %wa = zext i64 %a to i128\n  %wb = zext i64 %b to i128\n  %product = mul i128 %wa, %wb\n  %high = lshr i128 %product, 64\n  %out = trunc i128 %high to i64\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_smulh(i64 %a, i64 %b) {\nentry:\n  %wa = sext i64 %a to i128\n  %wb = sext i64 %b to i128\n  %product = mul i128 %wa, %wb\n  %high = ashr i128 %product, 64\n  %out = trunc i128 %high to i64\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_replicate(i64 %element0, i64 %esize, i64 %width) {\nentry:\n  %element = call i64 @axis_sem64_mask(i64 %element0, i64 %esize)\n  br label %loop\nloop:\n  %pos = phi i64 [ 0, %entry ], [ %next, %body ]\n  %acc = phi i64 [ 0, %entry ], [ %acc2, %body ]\n  %go = icmp ult i64 %pos, %width\n  br i1 %go, label %body, label %done\nbody:\n  %sh = shl i64 %element, %pos\n  %acc2 = or i64 %acc, %sh\n  %next = add i64 %pos, %esize\n  br label %loop\ndone:\n  %out = call i64 @axis_sem64_mask(i64 %acc, i64 %width)\n  ret i64 %out\n}\n\ndefine internal { i64, i64, i64 } @axis_a64_decode_masks(i64 %n, i64 %immr, i64 %imms, i64 %width) {\nentry:\n  %nb = and i64 %n, 1\n  %nhigh = shl i64 %nb, 6\n  %notimms = xor i64 %imms, -1\n  %low = and i64 %notimms, 63\n  %encoded = or i64 %nhigh, %low\n  %iszero = icmp eq i64 %encoded, 0\n  br i1 %iszero, label %none, label %have\nhave:\n  %lz = call i64 @llvm.ctlz.i64(i64 %encoded, i1 true)\n  %len = sub i64 63, %lz\n  %small = icmp ult i64 %len, 1\n  br i1 %small, label %none, label %ok\nnone:\n  ret { i64, i64, i64 } zeroinitializer\nok:\n  %one = shl i64 1, %len\n  %levels = sub i64 %one, 1\n  %s = and i64 %imms, %levels\n  %r = and i64 %immr, %levels\n  %d0 = sub i64 %s, %r\n  %diff = and i64 %d0, %levels\n  %esize = shl i64 1, %len\n  %s1 = add i64 %s, 1\n  %welem = call i64 @axis_sem64_mask(i64 -1, i64 %s1)\n  %d1 = add i64 %diff, 1\n  %telem = call i64 @axis_sem64_mask(i64 -1, i64 %d1)\n  %rotated = call i64 @axis_a64_shift_reg(i64 %welem, i64 3, i64 %r, i64 %esize)\n  %wm = call i64 @axis_a64_replicate(i64 %rotated, i64 %esize, i64 %width)\n  %tm = call i64 @axis_a64_replicate(i64 %telem, i64 %esize, i64 %width)\n  %p0 = insertvalue { i64, i64, i64 } undef, i64 %wm, 0\n  %p1 = insertvalue { i64, i64, i64 } %p0, i64 %tm, 1\n  %p2 = insertvalue { i64, i64, i64 } %p1, i64 %s, 2\n  ret { i64, i64, i64 } %p2\n}\n\ndefine internal i64 @axis_a64_wmask(i64 %n, i64 %immr, i64 %imms, i64 %width) {\nentry:\n  %m = call { i64, i64, i64 } @axis_a64_decode_masks(i64 %n, i64 %immr, i64 %imms, i64 %width)\n  %wm = extractvalue { i64, i64, i64 } %m, 0\n  ret i64 %wm\n}\n\ndefine internal i64 @axis_a64_ubfm(i64 %src, i64 %immr, i64 %imms, i64 %width) {\nentry:\n  %is64 = icmp eq i64 %width, 64\n  %n = zext i1 %is64 to i64\n  %m = call { i64, i64, i64 } @axis_a64_decode_masks(i64 %n, i64 %immr, i64 %imms, i64 %width)\n  %wm = extractvalue { i64, i64, i64 } %m, 0\n  %tm = extractvalue { i64, i64, i64 } %m, 1\n  %rot = call i64 @axis_a64_shift_reg(i64 %src, i64 3, i64 %immr, i64 %width)\n  %a = and i64 %rot, %wm\n  %out = and i64 %a, %tm\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_sbfm(i64 %src, i64 %immr, i64 %imms, i64 %width) {\nentry:\n  %is64 = icmp eq i64 %width, 64\n  %n = zext i1 %is64 to i64\n  %m = call { i64, i64, i64 } @axis_a64_decode_masks(i64 %n, i64 %immr, i64 %imms, i64 %width)\n  %wm = extractvalue { i64, i64, i64 } %m, 0\n  %tm = extractvalue { i64, i64, i64 } %m, 1\n  %s = extractvalue { i64, i64, i64 } %m, 2\n  %rot = call i64 @axis_a64_shift_reg(i64 %src, i64 3, i64 %immr, i64 %width)\n  %bot = and i64 %rot, %wm\n  %srcm = call i64 @axis_sem64_mask(i64 %src, i64 %width)\n  %shifted = lshr i64 %srcm, %s\n  %bit = and i64 %shifted, 1\n  %isneg = icmp ne i64 %bit, 0\n  %allones = call i64 @axis_sem64_mask(i64 -1, i64 %width)\n  %top = select i1 %isneg, i64 %allones, i64 0\n  %ntm = xor i64 %tm, -1\n  %hi = and i64 %top, %ntm\n  %lo = and i64 %bot, %tm\n  %joined = or i64 %hi, %lo\n  %masked = call i64 @axis_sem64_mask(i64 %joined, i64 %width)\n  ; A logical immediate the architecture leaves undefined decodes to an\n  ; empty mask, and the answer is zero -- which is what the golden model\n  ; has always said and what the C helper and the SMT definition say now.\n  %valid = icmp ne i64 %wm, 0\n  %out = select i1 %valid, i64 %masked, i64 0\n  ret i64 %out\n}\n\ndefine internal i64 @axis_a64_bfm(i64 %dst, i64 %src, i64 %immr, i64 %imms, i64 %width) {\nentry:\n  %is64 = icmp eq i64 %width, 64\n  %n = zext i1 %is64 to i64\n  %m = call { i64, i64, i64 } @axis_a64_decode_masks(i64 %n, i64 %immr, i64 %imms, i64 %width)\n  %wm = extractvalue { i64, i64, i64 } %m, 0\n  %tm = extractvalue { i64, i64, i64 } %m, 1\n  %dstm = call i64 @axis_sem64_mask(i64 %dst, i64 %width)\n  %nwm = xor i64 %wm, -1\n  %keep = and i64 %dstm, %nwm\n  %rot = call i64 @axis_a64_shift_reg(i64 %src, i64 3, i64 %immr, i64 %width)\n  %ins = and i64 %rot, %wm\n  %bot = or i64 %keep, %ins\n  %ntm = xor i64 %tm, -1\n  %hi = and i64 %dstm, %ntm\n  %lo = and i64 %bot, %tm\n  %joined = or i64 %hi, %lo\n  %masked = call i64 @axis_sem64_mask(i64 %joined, i64 %width)\n  ; A logical immediate the architecture leaves undefined decodes to an\n  ; empty mask, and the answer is zero -- which is what the golden model\n  ; has always said and what the C helper and the SMT definition say now.\n  %valid = icmp ne i64 %wm, 0\n  %out = select i1 %valid, i64 %masked, i64 0\n  ret i64 %out\n}\n\n";

/// How each AArch64 operator is called: its argument count, and whether the
/// evaluation width is passed as a trailing argument. Mirrors the C dispatch in
/// `emit::lift` so the two cannot describe different functions.
fn a64_helper(name: &str) -> Option<(usize, bool)> {
    Some(match name {
        "a64_logic_nzcv" => (1, true),
        "a64_add_nzcv" | "a64_sub_nzcv" => (2, true),
        "a64_adc_nzcv" | "a64_sbc_nzcv" => (3, true),
        "a64_shift_reg" | "a64_extend_reg" => (3, true),
        "a64_cond_holds" => (2, false),
        "a64_umulh" | "a64_smulh" => (2, false),
        // The bitmask-immediate family: `wmask` builds the mask an AND/ORR/EOR
        // immediate denotes, and the bitfield moves use the same decode.
        "a64_wmask" | "a64_ubfm" | "a64_sbfm" => (3, true),
        "a64_bfm" => (4, true),
        _ => return None,
    })
}

/// Whether any entry in the document uses an AArch64-specific operator.
pub(crate) fn document_uses_a64_ops(document: &Document) -> bool {
    let uses = |text: &str| text.contains("(a64_");
    document.instructions.iter().any(|instruction| {
        uses(&instruction.formal_semantics)
            || instruction.behavior.as_ref().is_some_and(|behavior| {
                behavior.effects.iter().any(|effect| {
                    uses(&crate::effects::render_semexpr(&effect.value.expr))
                        || effect
                            .guard
                            .as_ref()
                            .is_some_and(|guard| uses(&crate::effects::render_semexpr(&guard.expr)))
                })
            })
    })
}

/// Replace each AArch64 operator application with a fresh symbol bound to the
/// temp holding its result, so what is left is portable semantics the typed IR
/// can lower. The substituted names are SSA temps, which is why they are also
/// added to the allowed symbol set.
fn hoist_a64_ops(
    expr: &SemanticExpr,
    width: u32,
    word: Word,
    symbols: &mut Vec<String>,
    renames: &std::collections::HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<SemanticExpr> {
    let SemanticExpr::List(items) = expr else {
        return Some(expr.clone());
    };
    if let Some(SemanticExpr::Atom(head)) = items.first() {
        if let Some((arity, passes_width)) = a64_helper(head) {
            // These helpers are AArch64's, and AArch64 evaluates at 64 bits.
            if word.bits != 64 {
                return None;
            }
            // An explicit type atom sets the evaluation width for the call.
            let (call_width, arguments) = match items.get(1) {
                Some(SemanticExpr::Atom(atom)) if crate::ir::type_atom_bits(atom).is_some() => {
                    (crate::ir::type_atom_bits(atom)?, &items[2..])
                }
                _ => (width, &items[1..]),
            };
            if arguments.len() != arity {
                return None;
            }
            let mut lowered = Vec::new();
            for argument in arguments {
                let hoisted =
                    hoist_a64_ops(argument, call_width, word, symbols, renames, body, counter)?;
                lowered.push(llvm_effect_expr(
                    &hoisted, call_width, word, symbols, renames, body, counter,
                )?);
            }
            if passes_width {
                lowered.push(call_width.to_string());
            }
            let result = llvm_fresh(counter);
            let call_args = lowered
                .iter()
                .map(|value| format!("i64 {value}"))
                .collect::<Vec<_>>()
                .join(", ");
            body.push_str(&format!(
                "  {result} = call i64 @axis_{head}({call_args})\n"
            ));
            let name = result.trim_start_matches('%').to_string();
            symbols.push(name.clone());
            return Some(SemanticExpr::Atom(name));
        }
    }
    // An AArch64 operator without a helper — the bitmask family (`a64_wmask`,
    // `a64_bfm` and the bitfield moves) — is withheld here rather than left in
    // place: leaving it would hand the caller an expression that still looks
    // like it needs hoisting, and the caller would ask again forever.
    if let Some(SemanticExpr::Atom(head)) = items.first() {
        if head.starts_with("a64_") {
            return None;
        }
    }
    let mut rewritten = Vec::with_capacity(items.len());
    for item in items {
        rewritten.push(hoist_a64_ops(item, width, word, symbols, renames, body, counter)?);
    }
    Some(SemanticExpr::List(rewritten))
}

/// Lower an atomic read-modify-write pair to one native LLVM atomic
/// instruction, or `None` when the behavior is not that shape.
///
/// AXIS models these as two effects — a register set from an `atomic_load`,
/// then an atomic store to the same address whose value may depend on what was
/// loaded — held together by being one architectural transaction. Emitting them
/// as a separate load and store would give the same answer on one thread, and
/// the differential gate (which runs one thread) could not tell the difference:
/// it would be a lowering that is wrong in exactly the way nothing here can
/// observe. So the pair is either fused into a single `atomicrmw`/`cmpxchg`,
/// where indivisibility is carried by construction, or withheld.
///
/// The recognized shapes, which are the whole AArch64 atomic surface:
///
/// * `store <op>(loaded, src)` → `atomicrmw <op>`. `LDCLR`'s bit-clear spells
///   itself `and(loaded, not src)`, so the complement is computed first and the
///   operation is a plain `and`.
/// * `store src` → `atomicrmw xchg` (the `SWP` family).
/// * `store src` guarded by `loaded == <the destination's input value>` →
///   `cmpxchg` (the `CAS` family). That guard is exactly compare-and-swap's
///   comparison, and `__input_<name>` is the operand's value before this
///   instruction's own writes, which the executors bind for the same reason.
///
/// Orderings pair off the way AArch64's A and L bits do: a relaxed load with a
/// release store is `release`, an acquire load with a relaxed store is
/// `acquire`, both is `acq_rel`, neither is `monotonic`.
/// Lower a PAIRED compare-and-swap to one double-width `cmpxchg`, or `None`.
///
/// `CASP` swaps two consecutive registers against two consecutive words of
/// memory, and AXIS writes that as four effects in one `atomic-group`: a load
/// into each of the pair, then a store of each source guarded by *both* halves
/// having matched. That is a single architectural transaction, and the only
/// thing in LLVM that is also a single transaction over both words is a
/// `cmpxchg` at twice the element width -- which is exactly what the hardware
/// does, since `casp` operates on a register pair as one 128-bit (or 64-bit)
/// quantity.
///
/// Lowering the four effects separately would be the same mistake the two-effect
/// fusion exists to avoid, one word further: two independent compare-and-swaps
/// can both succeed, both fail, or -- the case that matters -- one of each,
/// which the instruction cannot do. A differential gate running one thread
/// could not tell the difference.
fn llvm_atomic_cas_pair(
    instruction: &crate::ast::Instruction,
    behavior: &crate::effects::Behavior,
    word: Word,
    bound: Option<(&[String], &std::collections::HashMap<String, String>)>,
    counter: &mut u32,
) -> Option<AtomicPair> {
    use crate::effects::{Loc, MemoryOrder};
    let [lo_load, hi_load, lo_store, hi_store] = &behavior.effects[..] else {
        return None;
    };
    let (Loc::Reg(lo_dest), Loc::Reg(hi_dest)) = (&lo_load.loc, &hi_load.loc) else {
        return None;
    };
    if lo_load.guard.is_some() || hi_load.guard.is_some() {
        return None;
    }
    if !lo_load.value.load_atomic || !hi_load.value.load_atomic {
        return None;
    }
    let Loc::Mem { addr: lo_addr, width: elem, order: store_order, atomic: true } =
        &lo_store.loc
    else {
        return None;
    };
    let Loc::Mem { addr: hi_addr, width: hi_width, order: hi_order, atomic: true } =
        &hi_store.loc
    else {
        return None;
    };
    if hi_width != elem || hi_order != store_order {
        return None;
    }
    // Two elements, and LLVM needs a whole integer type for the pair.
    if !matches!(*elem, 8 | 16 | 32 | 64) {
        return None;
    }
    let pair_bits = elem * 2;

    // The low half addresses what the low load read, and the high half sits one
    // element further along. Comparing the rendered text is how the two-effect
    // fusion checks the same thing: these are surface expressions, and the one
    // that matters is whether they name the same place.
    let render = crate::effects::render_semexpr;
    let SemanticExpr::List(lo_items) = &lo_load.value.expr else {
        return None;
    };
    let SemanticExpr::List(hi_items) = &hi_load.value.expr else {
        return None;
    };
    let base = lo_items.last()?;
    if render(base) != render(&lo_addr.expr) {
        return None;
    }
    let stepped = render(hi_items.last()?);
    if stepped != render(&hi_addr.expr) {
        return None;
    }
    // The high half is one element past the low one. Built rather than pattern
    // matched, so a description that steps by the wrong distance is refused
    // instead of being lowered as if it had stepped by the right one.
    let expected_step = render(&SemanticExpr::List(vec![
        SemanticExpr::Atom("add".to_string()),
        SemanticExpr::Atom(format!("i{}", word.bits)),
        base.clone(),
        SemanticExpr::Atom((elem / 8).to_string()),
    ]));
    if stepped != expected_step {
        return None;
    }

    // Both stores happen under one condition, and it is compare-and-swap's:
    // each half of the loaded pair equals that register's value on entry.
    let guard = lo_store.guard.as_ref()?;
    if render(&guard.expr) != render(&hi_store.guard.as_ref()?.expr) {
        return None;
    }
    if !cas_pair_expected(&guard.expr, lo_dest, hi_dest) {
        return None;
    }

    let owned_symbols = effect_symbols(instruction, &[]);
    let owned_renames = std::collections::HashMap::new();
    let (symbols, renames) = match bound {
        Some((symbols, renames)) => (symbols.to_vec(), renames.clone()),
        None => (owned_symbols, owned_renames),
    };
    let mut body = String::new();
    let address = llvm_effect_expr(
        &lo_addr.expr, lo_addr.width, word, &symbols, &renames, &mut body, counter,
    )?;
    let pointer = llvm_byte_pointer(&address, pair_bits, word, &mut body, counter);

    // What the pair holds on entry, and what it is to become. The entry value
    // of a destination is just its parameter: nothing has renamed it yet,
    // because the loaded value went to a fresh temp. That is the same reasoning
    // the single-word fusion uses, and `cas_expected_symbol` confirmed above
    // that this is what the guard compares.
    let expected = llvm_join_pair(
        &SemanticExpr::Atom(lo_dest.clone()),
        &SemanticExpr::Atom(hi_dest.clone()),
        *elem, word, &symbols, &renames, &mut body, counter,
    )?;
    let desired = llvm_join_pair(
        &lo_store.value.expr, &hi_store.value.expr,
        *elem, word, &symbols, &renames, &mut body, counter,
    )?;

    let ordering = match (lo_load.value.load_order, store_order) {
        (MemoryOrder::Acquire, MemoryOrder::Release) => "acq_rel",
        (MemoryOrder::Acquire, _) => "acquire",
        (_, MemoryOrder::Release) => "release",
        _ => "monotonic",
    };
    // A failure ordering may not exceed the success ordering and may not be a
    // release, the same rule the single-word fusion follows.
    let failure = match ordering {
        "acq_rel" | "acquire" => "acquire",
        _ => "monotonic",
    };
    let pair_ty = format!("i{pair_bits}");
    let paired = llvm_fresh(counter);
    body.push_str(&format!(
        "  {paired} = cmpxchg {pair_ty}* {pointer}, {pair_ty} {expected}, {pair_ty} {desired} {ordering} {failure}\n"
    ));
    let old = llvm_fresh(counter);
    body.push_str(&format!(
        "  {old} = extractvalue {{ {pair_ty}, i1 }} {paired}, 0\n"
    ));
    let (low, high) = llvm_split_pair(&old, *elem, word, &mut body, counter);
    Some(AtomicPair {
        body,
        writes: vec![(lo_dest.clone(), low), (hi_dest.clone(), high)],
        consumed: 4,
    })
}

/// Lower a PAIRED atomic load to one double-width `load atomic`, or `None`.
///
/// `LDXP` reads two consecutive registers from two consecutive words as a
/// single transaction -- AXIS marks it `atomic-group`, the same as `CASP` --
/// and the only thing in LLVM that is also one transaction over both words is
/// a load at twice the element width. LLVM selects `ldxp` for it on AArch64,
/// which is the instruction being lifted.
///
/// Unlike the compare-and-swap forms this consumes only the two loads. What
/// follows them is the exclusive monitor -- the address, the size, and the
/// valid bit -- and that is ordinary architectural state, which every consumer
/// of this description already carries and writes. There is nothing to
/// approximate: `consumed` says two, and the caller lowers the rest normally.
fn llvm_atomic_load_pair(
    instruction: &crate::ast::Instruction,
    behavior: &crate::effects::Behavior,
    word: Word,
    bound: Option<(&[String], &std::collections::HashMap<String, String>)>,
    counter: &mut u32,
) -> Option<AtomicPair> {
    use crate::effects::Loc;
    // An atomic STORE anywhere means this is a read-modify-write, and splitting
    // one is the mistake the whole fusion exists to prevent. Only a behavior
    // whose atomic part is purely reads can be taken apart this way.
    if behavior
        .effects
        .iter()
        .any(|effect| matches!(effect.loc, Loc::Mem { atomic: true, .. }))
    {
        return None;
    }
    let [lo_load, hi_load, ..] = &behavior.effects[..] else {
        return None;
    };
    let (Loc::Reg(lo_dest), Loc::Reg(hi_dest)) = (&lo_load.loc, &hi_load.loc) else {
        return None;
    };
    if lo_load.guard.is_some() || hi_load.guard.is_some() {
        return None;
    }
    if !lo_load.value.load_atomic || !hi_load.value.load_atomic {
        return None;
    }
    if lo_load.value.load_order != hi_load.value.load_order {
        return None;
    }
    let elem = lo_load.value.width;
    if elem != hi_load.value.width || !matches!(elem, 8 | 16 | 32 | 64) {
        return None;
    }
    let render = crate::effects::render_semexpr;
    let SemanticExpr::List(lo_items) = &lo_load.value.expr else {
        return None;
    };
    let SemanticExpr::List(hi_items) = &hi_load.value.expr else {
        return None;
    };
    let base = lo_items.last()?;
    // The high half is one element past the low one, built rather than matched,
    // so a description stepping by the wrong distance is refused.
    let expected_step = render(&SemanticExpr::List(vec![
        SemanticExpr::Atom("add".to_string()),
        SemanticExpr::Atom(format!("i{}", word.bits)),
        base.clone(),
        SemanticExpr::Atom((elem / 8).to_string()),
    ]));
    if render(hi_items.last()?) != expected_step {
        return None;
    }

    let owned_symbols = effect_symbols(instruction, &[]);
    let owned_renames = std::collections::HashMap::new();
    let (symbols, renames) = match bound {
        Some((symbols, renames)) => (symbols.to_vec(), renames.clone()),
        None => (owned_symbols, owned_renames),
    };
    let mut body = String::new();
    let address = llvm_effect_expr(
        base, lo_load.value.load_address_width?, word, &symbols, &renames,
        &mut body, counter,
    )?;
    let pair_bits = elem * 2;
    let pointer = llvm_byte_pointer(&address, pair_bits, word, &mut body, counter);
    let ordering = match lo_load.value.load_order {
        crate::effects::MemoryOrder::Acquire => "acquire",
        _ => "monotonic",
    };
    let pair_ty = format!("i{pair_bits}");
    let loaded = llvm_fresh(counter);
    body.push_str(&format!(
        "  {loaded} = load atomic {pair_ty}, {pair_ty}* {pointer} {ordering}, \
align {}\n",
        pair_bits / 8
    ));
    let (low, high) = llvm_split_pair(&loaded, elem, word, &mut body, counter);
    Some(AtomicPair {
        body,
        writes: vec![(lo_dest.clone(), low), (hi_dest.clone(), high)],
        consumed: 2,
    })
}

/// Whether the guard compares BOTH halves of the pair against their entry
/// values -- which is what makes the four effects one compare-and-swap.
///
/// Checked structurally, by asking `cas_expected_symbol` about each half, and
/// not by looking for `__input_` in the rendered text: a guard that tested one
/// half twice mentions both names and is not a paired comparison, and lowering
/// it as one would invent the comparison the description never made.
fn cas_pair_expected(guard: &SemanticExpr, lo: &str, hi: &str) -> bool {
    let SemanticExpr::List(items) = guard else {
        return false;
    };
    let (Some(SemanticExpr::Atom(op)), 3) = (items.first(), items.len()) else {
        return false;
    };
    if op != "and" {
        return false;
    }
    let halves = (
        cas_expected_symbol(&items[1], lo),
        cas_expected_symbol(&items[2], hi),
    );
    // Either order: the description may compare the high half first.
    matches!(halves, (Some(_), Some(_)))
        || matches!(
            (
                cas_expected_symbol(&items[1], hi),
                cas_expected_symbol(&items[2], lo),
            ),
            (Some(_), Some(_))
        )
}

/// Two word-width values joined into one of twice the element width, low half
/// first -- the layout a register pair has in memory on a little-endian machine.
fn llvm_join_pair(
    low: &SemanticExpr,
    high: &SemanticExpr,
    elem: u32,
    word: Word,
    symbols: &[String],
    renames: &std::collections::HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<String> {
    let pair_bits = elem * 2;
    let pair_ty = format!("i{pair_bits}");
    let mut widen = |expr: &SemanticExpr| -> Option<String> {
        let value = llvm_effect_expr(expr, elem, word, symbols, renames, body, counter)?;
        // Only the element's own bits take part: the block's word may be wider
        // than the element, and whatever sits above it belongs to no half.
        let masked = llvm_fresh(counter);
        body.push_str(&format!(
            "  {masked} = call {} @{}mask({} {value}, {} {elem})\n",
            word.ty, word.prefix, word.ty, word.ty
        ));
        if pair_bits == word.bits {
            return Some(masked);
        }
        let widened = llvm_fresh(counter);
        body.push_str(&format!(
            "  {widened} = zext {} {masked} to {pair_ty}\n", word.ty
        ));
        Some(widened)
    };
    let low = widen(low)?;
    let high = widen(high)?;
    let shifted = llvm_fresh(counter);
    body.push_str(&format!("  {shifted} = shl {pair_ty} {high}, {elem}\n"));
    let joined = llvm_fresh(counter);
    body.push_str(&format!("  {joined} = or {pair_ty} {low}, {shifted}\n"));
    Some(joined)
}

/// The inverse: one double-width value back into two at the block's word.
fn llvm_split_pair(
    value: &str,
    elem: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> (String, String) {
    let pair_bits = elem * 2;
    let pair_ty = format!("i{pair_bits}");
    let shifted = llvm_fresh(counter);
    body.push_str(&format!("  {shifted} = lshr {pair_ty} {value}, {elem}\n"));
    let mut narrow = |source: &str| -> String {
        let out = llvm_fresh(counter);
        if pair_bits == word.bits {
            body.push_str(&format!(
                "  {out} = call {} @{}mask({} {source}, {} {elem})\n",
                word.ty, word.prefix, word.ty, word.ty
            ));
        } else {
            body.push_str(&format!(
                "  {out} = trunc {pair_ty} {source} to {}\n", word.ty
            ));
        }
        out
    };
    (narrow(value), narrow(&shifted))
}

pub(crate) fn llvm_atomic_pair(
    instruction: &crate::ast::Instruction,
    behavior: &crate::effects::Behavior,
    word: Word,
    bound: Option<(&[String], &std::collections::HashMap<String, String>)>,
    counter: &mut u32,
) -> Option<AtomicPair> {
    use crate::effects::{Loc, MemoryOrder};
    // The paired form first: it is four effects where this one wants two, so
    // the two shapes cannot be confused, and asking here keeps one entry point.
    if let Some(paired) =
        llvm_atomic_cas_pair(instruction, behavior, word, bound, counter)
    {
        return Some(paired);
    }
    // A paired atomic LOAD, which consumes only its two effects: what follows
    // is the exclusive monitor, and that is state the caller lowers itself.
    if let Some(paired) =
        llvm_atomic_load_pair(instruction, behavior, word, bound, counter)
    {
        return Some(paired);
    }
    let [load_effect, store_effect] = &behavior.effects[..] else {
        return None;
    };
    let Loc::Reg(dest) = &load_effect.loc else {
        return None;
    };
    let Loc::Mem {
        addr,
        width,
        order: store_order,
        atomic: true,
    } = &store_effect.loc
    else {
        return None;
    };
    if !load_effect.value.load_atomic || load_effect.guard.is_some() {
        return None;
    }
    // The load's address is the expression under the `atomic_load`; it has to be
    // the same place the store writes, or this is not one location's RMW.
    let SemanticExpr::List(load_items) = &load_effect.value.expr else {
        return None;
    };
    let load_addr = load_items.last()?;
    if crate::effects::render_semexpr(load_addr) != crate::effects::render_semexpr(&addr.expr) {
        return None;
    }
    if !matches!(*width, 8 | 16 | 32 | 64) {
        return None;
    }

    // An effect function's operands are its parameters, so the names stand for
    // themselves. A lifted region has already loaded them into SSA values, and
    // passes those bindings in.
    let owned_symbols = effect_symbols(instruction, &[]);
    let owned_renames = std::collections::HashMap::new();
    let (symbols, renames) = match bound {
        Some((symbols, renames)) => (symbols.to_vec(), renames.clone()),
        None => (owned_symbols, owned_renames),
    };
    let mut body = String::new();
    let address = llvm_effect_expr(
        &addr.expr,
        addr.width,
        word,
        &symbols,
        &renames,
        &mut body,
        counter,
    )?;
    let pointer = llvm_byte_pointer(&address, *width, word, &mut body, counter);

    // The stored value, read as a function of what the load produced.
    let ordering = match (load_effect.value.load_order, store_order) {
        (MemoryOrder::Acquire, MemoryOrder::Release) => "acq_rel",
        (MemoryOrder::Acquire, _) => "acquire",
        (_, MemoryOrder::Release) => "release",
        _ => "monotonic",
    };
    let access = format!("i{width}");
    let narrow = |value: &str, body: &mut String, counter: &mut u32| -> String {
        if *width == word.bits {
            return value.to_string();
        }
        let narrowed = llvm_fresh(counter);
        body.push_str(&format!(
            "  {narrowed} = trunc {} {value} to {access}\n",
            word.ty
        ));
        narrowed
    };

    let stored = &store_effect.value.expr;
    let result = match (&store_effect.guard, stored) {
        // CAS: the store fires only when the loaded value still matches what
        // the destination register held on entry.
        (Some(guard), _) => {
            let expected = cas_expected_symbol(&guard.expr, dest)?;
            let operand = llvm_effect_expr(
                stored,
                store_effect.value.width,
                word,
                &symbols,
                &renames,
                &mut body,
                counter,
            )?;
            let expected = llvm_effect_expr(
                &SemanticExpr::Atom(expected),
                store_effect.value.width,
                word,
                &symbols,
                &renames,
                &mut body,
                counter,
            )?;
            let expected = narrow(&expected, &mut body, counter);
            let operand = narrow(&operand, &mut body, counter);
            // A failure ordering may not be stronger than success, and may not
            // be a release; acquire survives, everything else drops to
            // monotonic.
            let failure = if matches!(ordering, "acquire" | "acq_rel") {
                "acquire"
            } else {
                "monotonic"
            };
            let paired = llvm_fresh(counter);
            body.push_str(&format!(
                // ⚠️ No `align`, unlike every plain load and store here, which
                // say `align 1` because AXIS's memory is bytes. An atomic that
                // omits it takes LLVM's default of NATURAL alignment, and that
                // is deliberate: on the machines AXIS describes an unaligned
                // atomic faults, so a lowering that assumes alignment is the
                // faithful one. `align 1` was tried and reverted -- it is
                // correct at any address, but LLVM answers it with a call to
                // `__atomic_compare_exchange`, and the stencil JIT cannot copy
                // a stencil that references a symbol which is not a hole. It
                // said so: "2 symbol(s) referenced that are not holes".
                //
                // What it costs is that a region feeding an atomic an address
                // an earlier instruction computed will fault where the value
                // models do not. `lift_region_check.py` does not draw those.
                "  {paired} = cmpxchg {access}* {pointer}, {access} {expected}, {access} {operand} {ordering} {failure}\n"
            ));
            let old = llvm_fresh(counter);
            body.push_str(&format!(
                "  {old} = extractvalue {{ {access}, i1 }} {paired}, 0\n"
            ));
            old
        }
        (None, expression) => {
            let (op, operand_expr) = atomicrmw_operation(expression, dest);
            let operand = llvm_effect_expr(
                &operand_expr,
                store_effect.value.width,
                word,
                &symbols,
                &renames,
                &mut body,
                counter,
            )?;
            let operand = narrow(&operand, &mut body, counter);
            let old = llvm_fresh(counter);
            body.push_str(&format!(
                // Natural alignment for the same reason as `cmpxchg` above.
                "  {old} = atomicrmw {op} {access}* {pointer}, {access} {operand} {ordering}\n"
            ));
            old
        }
    };

    // `atomicrmw` and `cmpxchg` both yield the value that was in memory, which
    // is what the register set takes — extended the way the load asks for.
    // RISC-V's 32-bit atomics on a 64-bit machine sign-extend their result;
    // AArch64's are all unsigned, which is why this was zero-extension only
    // until a second ISA arrived.
    let signed_load =
        matches!(load_items.get(2), Some(SemanticExpr::Atom(sign)) if sign == "signed");
    let widened = if *width == word.bits {
        result
    } else {
        let extended = llvm_fresh(counter);
        let how = if signed_load { "sext" } else { "zext" };
        body.push_str(&format!(
            "  {extended} = {how} {access} {result} to {}\n",
            word.ty
        ));
        extended
    };
    let out_width = instruction
        .operands
        .iter()
        .find(|operand| &operand.name == dest)
        .map(|operand| operand.width)
        .unwrap_or(word.bits);
    let masked = llvm_fresh(counter);
    body.push_str(&format!(
        "  {masked} = call {} @{}mask({} {widened}, {} {out_width})\n",
        word.ty, word.prefix, word.ty, word.ty
    ));
    Some(AtomicPair {
        body,
        writes: vec![(dest.clone(), masked)],
        consumed: 2,
    })
}

/// A fused read-modify-write: the IR that performs it, the temp holding the
/// value it loaded, and the operand that value is written to.
///
/// Returned rather than stored, because the two callers put it in different
/// places -- an effect function reports it through `%out`, and a lifted region
/// writes it straight into the register file.
pub(crate) struct AtomicPair {
    pub(crate) body: String,
    /// What the transaction leaves in registers: the destination operand's
    /// name and the SSA value now holding it, in write-slot order.
    ///
    /// A list rather than one pair, because `CASP` swaps a REGISTER PAIR: one
    /// `cmpxchg` at twice the width, whose old value comes back as two halves.
    /// A single result could not say that, and the shape was refused for it.
    pub(crate) writes: Vec<(String, String)>,
    pub(crate) consumed: usize,
}

/// The operand of a compare-and-swap's comparison: the guard must test the
/// loaded value against the destination register's value on entry, which the
/// typed IR spells `(input <operand>)`. In SSA that value is just the
/// parameter, because nothing has renamed it yet — the loaded value went to a
/// fresh temp.
fn cas_expected_symbol(guard: &SemanticExpr, dest: &str) -> Option<String> {
    let SemanticExpr::List(items) = guard else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    if op != "icmp_eq" || items.len() != 3 {
        return None;
    }
    // Each side is wrapped in an `(or W x 0)` width coercion by the frontend,
    // and the entry value is a further `(input x)`. Returns `(name, is_entry)`.
    fn peel(side: &SemanticExpr) -> Option<(String, bool)> {
        match side {
            SemanticExpr::Atom(name) => Some((name.clone(), false)),
            SemanticExpr::List(parts) => match parts.first()? {
                SemanticExpr::Atom(op) if op == "or" && parts.len() == 4 => peel(parts.get(2)?),
                SemanticExpr::Atom(op) if op == "input" && parts.len() == 2 => {
                    let (name, _) = peel(parts.get(1)?)?;
                    Some((name, true))
                }
                _ => None,
            },
        }
    }
    let lhs = peel(&items[1])?;
    let rhs = peel(&items[2])?;
    // One side is the value just loaded into `dest`, the other is what `dest`
    // held on entry; anything else is not a compare-and-swap.
    match (lhs, rhs) {
        ((loaded, false), (entry, true)) | ((entry, true), (loaded, false))
            if loaded == *dest && entry == *dest =>
        {
            Some(entry)
        }
        _ => None,
    }
}

/// Which `atomicrmw` operation a stored value spells, and the operand to give
/// it. A value that does not mention the loaded register is an exchange.
fn atomicrmw_operation(stored: &SemanticExpr, dest: &str) -> (&'static str, SemanticExpr) {
    let mentions = |expr: &SemanticExpr| {
        crate::effects::render_semexpr(expr)
            .split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == dest)
    };
    if !mentions(stored) {
        return ("xchg", stored.clone());
    }
    if let SemanticExpr::List(items) = stored {
        if let Some(SemanticExpr::Atom(op)) = items.first() {
            // `(op W loaded operand)` — the type atom is items[1].
            if items.len() == 4 {
                let (lhs, rhs) = (&items[2], &items[3]);
                let other = if mentions(lhs) { rhs } else { lhs };
                let name = match op.as_str() {
                    "add" => Some("add"),
                    "sub" => Some("sub"),
                    "or" => Some("or"),
                    "xor" => Some("xor"),
                    "and" => Some("and"),
                    "max" => Some("max"),
                    "min" => Some("min"),
                    "maxu" => Some("umax"),
                    "minu" => Some("umin"),
                    _ => None,
                };
                if let Some(name) = name {
                    return (name, other.clone());
                }
            }
        }
    }
    ("unsupported", stored.clone())
}

/// The LLVM fence ordering a barrier kind maps to, or `None` when the barrier
/// has no representation in the IR.
///
/// Data barriers (`dmb`, `dsb`) order memory, which is what `fence` means.
/// Instruction and speculation barriers (`isb`, `csdb`, `ssbb`, `pssbb`, `sb`)
/// constrain the pipeline rather than the memory model, and LLVM has nothing
/// that says so — emitting a memory fence for them would claim something the
/// architecture does not, so they are withheld with the reason named.
pub(crate) fn fence_ordering(kind: &str) -> Option<&'static str> {
    // Which barriers order memory is the table's to say, not this file's. It
    // had its own copy of the list, so RISC-V's `fence` would have been
    // accepted by the frontend and then silently emitted no fence here.
    match crate::effects::barrier_kind(kind) {
        Some(found) if found.orders_memory => Some("seq_cst"),
        _ => None,
    }
}

/// The `%out` preamble every effect function starts with: the fall-through pc,
/// no trap, and every write slot cleared. A guarded `set` that is not taken has
/// to read as "did not write" rather than as whatever the caller's scratch array
/// happened to hold.
fn effect_prologue(word: Word, counter: &mut u32) -> String {
    let ty = word.ty;
    let mut body = String::new();
    // Dotted names cannot collide with an operand's identifier.
    let fallthrough = llvm_fresh(counter);
    body.push_str(&format!("  {fallthrough} = add {ty} %pc, 4\n"));
    body.push_str(&format!(
        "  %axis.next = getelementptr {ty}, {ty}* %out, i32 2\n  store {ty} {fallthrough}, {ty}* %axis.next\n  %axis.trap = getelementptr {ty}, {ty}* %out, i32 3\n  store {ty} 0, {ty}* %axis.trap\n"
    ));
    for index in 0..crate::effects::EFFECT_MAX_WRITES {
        let (value_slot, wrote_slot) = effect_write_slots(index);
        body.push_str(&format!(
            "  %axis.value{index} = getelementptr {ty}, {ty}* %out, i32 {value_slot}\n  store {ty} 0, {ty}* %axis.value{index}\n  %axis.wrote{index} = getelementptr {ty}, {ty}* %out, i32 {wrote_slot}\n  store {ty} 0, {ty}* %axis.wrote{index}\n"
        ));
    }
    body
}

/// Where write `index` reports its value and its fired flag in `%out`.
/// See [`crate::effects::EFFECT_OUT_SLOTS`] for the layout and why write #0
/// keeps slots 0 and 1.
fn effect_write_slots(index: usize) -> (usize, usize) {
    match index {
        0 => (0, 1),
        n => (2 + 2 * n, 3 + 2 * n),
    }
}

/// Redirect symbols to the SSA values that currently hold them.
///
/// The executors evaluate an instruction's effects in order against a mutable
/// register file, so `rn = rn + imm; rt = Mem64[rn]` loads from the *updated*
/// base. An SSA parameter cannot be updated, so each register write records the
/// temp holding its new value and later effects lower against that instead.
/// Renaming the typed IR rather than patching the emitted text means the
/// substitution happens where symbols are still structured, and one lowering
/// path still produces the code.
fn rename_symbols(sem: &Sem, renames: &std::collections::HashMap<String, String>) -> Sem {
    match sem {
        Sem::Sym(name) => Sem::Sym(renames.get(name).cloned().unwrap_or_else(|| name.clone())),
        Sem::Int { value, width } => Sem::Int {
            value: *value,
            width: *width,
        },
        Sem::App { op, width, args } => Sem::App {
            op: *op,
            width: *width,
            args: args.iter().map(|arg| rename_symbols(arg, renames)).collect(),
        },
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => Sem::Ext {
            op: *op,
            width: *width,
            from_bits: *from_bits,
            arg: Box::new(rename_symbols(arg, renames)),
        },
        Sem::Call { name, width, args } => Sem::Call {
            name: name.clone(),
            width: *width,
            args: args.iter().map(|(param, arg)| (*param, rename_symbols(arg, renames))).collect(),
        },
    }
}

/// Why this instruction's behavior does not fit the effect ABI, or `None` when
/// it does.
///
/// `%out` carries exactly one written register value plus a flag, and every
/// operand arrives as an immutable SSA parameter. Two kinds of behavior fall
/// outside that:
///
/// * **More register writes than `%out` carries.** AArch64's `ldp` with
///   writeback writes three registers, which is the most any instruction here
///   needs; `effects::EFFECT_MAX_WRITES` allows four. Emitting one beyond that
///   would drop a write silently.
/// A later effect *reading* a register an earlier one wrote used to be withheld
/// here too. It no longer is: `rename_symbols` threads each write's SSA value
/// forward, which is what the executors' mutable register file does. That covers
/// the indexed stores, whose base update is read by their own memory effect.
/// The width of the operand a register effect writes, or 0 when the effect does
/// not name one.
fn effect_dest_width(
    instruction: &crate::ast::Instruction,
    effect: &crate::effects::Effect,
) -> u32 {
    use crate::effects::Loc;
    let Loc::Reg(dest) = &effect.loc else {
        return 0;
    };
    instruction
        .operands
        .iter()
        .find(|operand| &operand.name == dest)
        .map(|operand| operand.width)
        .unwrap_or(0)
}

/// How many `word`-sized limbs a register effect writes. One for everything
/// that fits a slot; two for a 128-bit vector register, which is how the
/// register file stores it.
fn effect_limbs(
    instruction: &crate::ast::Instruction,
    effect: &crate::effects::Effect,
    word: Word,
) -> usize {
    let width = effect_dest_width(instruction, effect);
    if width <= word.bits {
        1
    } else {
        width.div_ceil(word.bits) as usize
    }
}

/// Whether a value wider than one slot can be lowered as whole limbs.
///
/// A 128-bit register is two 64-bit limbs, so an access that *moves* one --
/// `ldr q0, [x1]` and its store -- is two 64-bit accesses and nothing more.
/// That is the only wide shape lowered here. A 128-bit value that is computed
/// rather than moved would need real i128 arithmetic in the effect ABI, and the
/// ABI's `%out` is an array of register slots: it can carry the limbs of a
/// value, not a number wider than the file's slots. So the split is offered
/// only where the description is already limb-shaped, and everything else keeps
/// the refusal it had.
fn effect_is_whole_limbs(
    instruction: &crate::ast::Instruction,
    effect: &crate::effects::Effect,
    word: Word,
) -> bool {
    use crate::effects::Loc;
    if effect.guard.is_some() {
        return false;
    }
    match &effect.loc {
        // A register set whose value is a plain load of exactly the
        // destination's width: every limb comes from memory, none from
        // arithmetic.
        Loc::Reg(_) => {
            let width = effect_dest_width(instruction, effect);
            if width <= word.bits {
                return true;
            }
            if width % word.bits != 0 {
                return false;
            }
            match &effect.value.expr {
                SemanticExpr::List(items)
                    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "load")
                        && matches!(items.len(), 4 | 5) =>
                {
                    items.get(1).and_then(|a| llvm_limb_access_width(a, word)) == Some(width)
                }
                _ => false,
            }
        }
        // A store of exactly one register's worth, whose value is that register
        // read plainly -- no expression to evaluate at 128 bits.
        Loc::Mem { width, .. } => {
            if *width <= word.bits {
                return true;
            }
            if width % word.bits != 0 {
                return false;
            }
            matches!(&effect.value.expr, SemanticExpr::Atom(name)
                if instruction.operands.iter().any(|operand|
                    &operand.name == name && operand.input && operand.width == *width))
        }
        _ => effect.value.width <= word.bits,
    }
}

/// Whether every effect is limb-shaped, so the function can be emitted at 64
/// bits with wide accesses split rather than withheld.
pub(crate) fn behavior_is_whole_limbs(
    instruction: &crate::ast::Instruction,
    behavior: &crate::effects::Behavior,
    word: Word,
) -> bool {
    behavior
        .effects
        .iter()
        .all(|effect| effect_is_whole_limbs(instruction, effect, word))
}

fn single_write_abi_cannot_express(
    instruction: &crate::ast::Instruction,
) -> Option<&'static str> {
    use crate::effects::Loc;
    let behavior = instruction.behavior.as_ref()?;
    let register_writes: usize = behavior
        .effects
        .iter()
        .filter(|effect| matches!(effect.loc, Loc::Reg(_) | Loc::FixedReg { .. }))
        .map(|effect| effect_limbs(instruction, effect, llvm_word(LLVM_EFFECT_MAX_WIDTH)))
        .sum();
    if register_writes > crate::effects::EFFECT_MAX_WRITES {
        return Some(
            "writes more registers than `%out` carries; raise\n\
             ; effects::EFFECT_MAX_WRITES if an ISA ever needs it",
        );
    }
    None
}

/// Lower one unguarded effect to LLVM IR statements.
fn llvm_effect_body(
    instruction: &crate::ast::Instruction,
    effect: &crate::effects::Effect,
    word: Word,
    write_index: usize,
    state_names: &[String],
    renames: &mut std::collections::HashMap<String, String>,
    counter: &mut u32,
) -> Option<String> {
    use crate::effects::Loc;
    let ty = word.ty;
    let symbols = effect_symbols(instruction, state_names);
    let mut body = String::new();
    match &effect.loc {
        Loc::Reg(dest) => {
            let out_width = instruction
                .operands
                .iter()
                .find(|operand| &operand.name == dest)
                .map(|operand| operand.width)
                .unwrap_or(32);
            // Wider than a slot means limbs. `ldr q0, [x1]` is two 64-bit
            // loads eight bytes apart reporting into two write slots -- the
            // same IR `ldp` already emits, because it is the same operation
            // written two ways. No extend and no mask: a whole limb needs
            // neither, and a partial one never reaches here.
            if out_width > word.bits {
                let items = match &effect.value.expr {
                    SemanticExpr::List(items) => items,
                    _ => return None,
                };
                let access = llvm_limb_access_width(items.get(1)?, word)?;
                let base = llvm_effect_expr(
                    items.last()?,
                    effect.value.load_address_width?,
                    word,
                    &symbols,
                    renames,
                    &mut body,
                    counter,
                )?;
                let bytes = (word.bits / 8) as u64;
                for limb in 0..(access / word.bits) as usize {
                    let address = if limb == 0 {
                        base.clone()
                    } else {
                        let bumped = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {bumped} = add {ty} {base}, {}\n",
                            limb as u64 * bytes
                        ));
                        bumped
                    };
                    let loaded =
                        llvm_memory_read(&address, word.bits, word, &mut body, counter);
                    let slot = write_index + limb;
                    body.push_str(&format!(
                        "  store {ty} {loaded}, {ty}* %axis.value{slot}\n  store {ty} 1, {ty}* %axis.wrote{slot}\n"
                    ));
                }
                return Some(body);
            }
            // A register set whose value is a load peels into a memory read
            // plus sign/zero extend, exactly as the C effect functions do.
            let value = llvm_effect_value(
                effect, out_width, word, &symbols, renames, &mut body, counter,
            )?;
            let masked = llvm_fresh(counter);
            body.push_str(&format!(
                "  {masked} = call {ty} @{}mask({ty} {value}, {ty} {out_width})\n  store {ty} {masked}, {ty}* %axis.value{write_index}\n  store {ty} 1, {ty}* %axis.wrote{write_index}\n",
                word.prefix
            ));
            // Later effects read the value this one wrote, not the parameter.
            renames.insert(dest.clone(), masked.trim_start_matches('%').to_string());
            Some(body)
        }
        Loc::Mem { addr, width, .. } if *width > word.bits => {
            // The mirror of the wide load. The value is a plain register read
            // -- `effect_is_whole_limbs` allows nothing else here -- so its
            // limbs are parameters, and each goes to its own eight bytes.
            let base = llvm_effect_expr(
                &addr.expr,
                addr.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            let SemanticExpr::Atom(name) = &effect.value.expr else {
                return None;
            };
            let bytes = (word.bits / 8) as u64;
            for limb in 0..(*width / word.bits) as usize {
                let address = if limb == 0 {
                    base.clone()
                } else {
                    let bumped = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {bumped} = add {ty} {base}, {}\n",
                        limb as u64 * bytes
                    ));
                    bumped
                };
                let limb_value = format!("%{}", limb_param(name, limb));
                llvm_memory_write(&address, &limb_value, word.bits, word, &mut body, counter);
            }
            Some(body)
        }
        Loc::Mem { addr, width, .. } => {
            let address = llvm_effect_expr(
                &addr.expr,
                addr.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            // ⚠️ `llvm_effect_value`, not `llvm_effect_expr`. A store's value
            // may be a LOAD -- a block copy is exactly that, memory to memory
            // in one effect -- and `load` is not an operator the pure IR has,
            // so lowering the value as an expression refused five instructions
            // across two corpora. The register-set path has peeled a load into
            // a memory read plus an extend all along; this is the same peeling
            // for the same reason, and an ordinary value falls through it
            // unchanged.
            let value = llvm_effect_value(
                effect,
                effect.value.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            llvm_memory_write(&address, &value, *width, word, &mut body, counter);
            Some(body)
        }
        Loc::Pc => {
            let target = llvm_effect_expr(
                &effect.value.expr,
                effect.value.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            body.push_str(&format!("  store {ty} {target}, {ty}* %axis.next\n"));
            Some(body)
        }
        Loc::Trap => {
            let cause = crate::effects::render_semexpr(&effect.value.expr);
            let id = crate::effects::TRAP_CAUSES
                .iter()
                .position(|known| *known == cause.trim())?
                + 1;
            body.push_str(&format!(
                "  store {ty} {id}, {ty}* %axis.trap\n  ret void\n"
            ));
            // A trap ends the block, so anything after it is unreachable; the
            // caller emits no further effects for this instruction.
            let resume = format!("trap{counter}.unreachable");
            *counter += 1;
            body.push_str(&format!("{resume}:\n"));
            Some(body)
        }
        Loc::State { name, width } => {
            let slot = state_names.iter().position(|known| known == name)?;
            // ⚠️ `llvm_effect_value`, for the same reason the store arm uses it:
            // a state write's value may be a LOAD. An exclusive monitor that
            // records the value it observed is exactly that, and `load` is not
            // an operator the pure IR has. Third arm to need this -- register
            // set, store, and now state -- which is the whole set.
            let value = llvm_effect_value(
                effect,
                effect.value.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            let masked = llvm_fresh(counter);
            let pointer = llvm_fresh(counter);
            body.push_str(&format!(
                "  {masked} = call {ty} @{}mask({ty} {value}, {ty} {width})\n  {pointer} = getelementptr {ty}, {ty}* %state, i32 {slot}\n  store {ty} {masked}, {ty}* {pointer}\n",
                word.prefix
            ));
            // A later effect reads what this one wrote, not the entry value.
            renames.insert(name.clone(), masked.trim_start_matches('%').to_string());
            Some(body)
        }
        // A fixed register write reports through the same slot machinery. What
        // makes it addressable is that the lift table publishes the index, so a
        // consumer mapping write `k` to the k-th register-writing effect finds a
        // constant there instead of an operand name.
        Loc::FixedReg { width, .. } => {
            let value = llvm_effect_expr(
                &effect.value.expr,
                effect.value.width,
                word,
                &symbols,
                renames,
                &mut body,
                counter,
            )?;
            let masked = llvm_fresh(counter);
            body.push_str(&format!(
                "  {masked} = call {ty} @{}mask({ty} {value}, {ty} {width})\n  store {ty} {masked}, {ty}* %axis.value{write_index}\n  store {ty} 1, {ty}* %axis.wrote{write_index}\n",
                word.prefix
            ));
            Some(body)
        }
        // A data barrier becomes a real `fence`. LLVM's fence carries an
        // ordering but no domain, so AArch64's inner/outer/non-shareable
        // options all lower to the strongest ordering: emitting a barrier
        // stronger than the architecture requires is conservative, never wrong,
        // and a consumer that needs the domain has the option value in the
        // artifacts. Like an atomic's indivisibility, this is carried by
        // construction — a single-threaded differential gate cannot observe it.
        // ⚠️ No LLVM spelling. A message out of the machine is not a store,
        // not a fence, and not a call to anything this module declares -- and
        // an intrinsic invented here would be a name with no meaning on the
        // other side of it. `None` is this emitter saying so; the C and Rust
        // executors carry the effect, and the golden model is what the gates
        // compare against.
        Loc::Port { .. } => None,
        Loc::Barrier { kind, .. } => {
            let ordering = fence_ordering(kind)?;
            body.push_str(&format!("  fence {ordering}\n"));
            Some(body)
        }
    }
}

/// Byte-addressed little-endian access against the flat `%mem` buffer.
pub(crate) fn llvm_memory_read(
    address: &str,
    access: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let pointer = llvm_byte_pointer(address, access, word, body, counter);
    let loaded = llvm_fresh(counter);
    body.push_str(&format!(
        "  {loaded} = load i{access}, i{access}* {pointer}, align 1\n"
    ));
    if access == word.bits {
        return loaded;
    }
    let widened = llvm_fresh(counter);
    body.push_str(&format!(
        "  {widened} = zext i{access} {loaded} to {}\n",
        word.ty
    ));
    widened
}

/// The same read, as the atomic the description says it is.
///
/// ⚠️ `align 1` is what an ordinary read states and is **invalid** on an atomic
/// one: LLVM requires an atomic access to state an alignment at least its own
/// size, and the hardware requires the address to have it. The caller's
/// harnesses align for the same reason -- see `atomic_alignment`.
pub(crate) fn llvm_memory_read_atomic(
    address: &str,
    access: u32,
    word: Word,
    ordering: &str,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let pointer = llvm_byte_pointer(address, access, word, body, counter);
    let loaded = llvm_fresh(counter);
    body.push_str(&format!(
        "  {loaded} = load atomic i{access}, i{access}* {pointer} {ordering}, align {}
",
        access / 8
    ));
    if access == word.bits {
        return loaded;
    }
    let widened = llvm_fresh(counter);
    body.push_str(&format!(
        "  {widened} = zext i{access} {loaded} to {}
",
        word.ty
    ));
    widened
}

/// A write, as the atomic the description says it is. See the read above for
/// why the alignment is stated rather than left at one.
pub(crate) fn llvm_memory_write_atomic(
    address: &str,
    value: &str,
    width: u32,
    word: Word,
    ordering: &str,
    body: &mut String,
    counter: &mut u32,
) {
    let pointer = llvm_byte_pointer(address, width, word, body, counter);
    let narrowed = if width == word.bits {
        value.to_string()
    } else {
        let cut = llvm_fresh(counter);
        body.push_str(&format!(
            "  {cut} = trunc {} {value} to i{width}
", word.ty
        ));
        cut
    };
    body.push_str(&format!(
        "  store atomic i{width} {narrowed}, i{width}* {pointer} {ordering}, align {}
",
        width / 8
    ));
}

/// A store that happens only when `condition` holds, as one instruction.
///
/// ⚠️ `llvm.masked.store` with a false mask performs **no store**, which is what
/// a guarded store needs and what the obvious alternatives do not give. Reading
/// the old value and selecting between it and the new one writes the same bytes
/// back, and a store of the same bytes is still a store to anything else
/// watching -- another thread, a watchpoint, a device. Branching would be exact
/// too, and needs a block, which a lowering with one entry and one exit has
/// nowhere to put.
///
/// So a store-conditional lowers here without a branch and without inventing a
/// write: RISC-V's `sc.w`/`sc.d` and AArch64's `stlxr` family, sixteen
/// instructions that were refused for wanting a block of their own.
pub(crate) fn llvm_masked_write(
    address: &str,
    value: &str,
    width: u32,
    condition: &str,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) {
    let pointer = llvm_byte_pointer(address, width, word, body, counter);
    let narrowed = if width == word.bits {
        value.to_string()
    } else {
        let temp = llvm_fresh(counter);
        body.push_str(&format!(
            "  {temp} = trunc {} {value} to i{width}\n",
            word.ty
        ));
        temp
    };
    let vector = llvm_fresh(counter);
    body.push_str(&format!(
        "  {vector} = insertelement <1 x i{width}> undef, i{width} {narrowed}, i32 0\n"
    ));
    let mask = llvm_fresh(counter);
    body.push_str(&format!(
        "  {mask} = insertelement <1 x i1> undef, i1 {condition}, i32 0\n"
    ));
    let cast = llvm_fresh(counter);
    body.push_str(&format!(
        "  {cast} = bitcast i{width}* {pointer} to <1 x i{width}>*\n"
    ));
    body.push_str(&format!(
        "  call void @llvm.masked.store.v1i{width}.p0v1i{width}(<1 x i{width}> {vector}, \
<1 x i{width}>* {cast}, i32 1, <1 x i1> {mask})\n"
    ));
}

/// The `masked.store` declarations a module needs, at every access width.
pub(crate) fn llvm_masked_store_declarations() -> String {
    let mut out = String::new();
    for width in [8u32, 16, 32, 64] {
        out.push_str(&format!(
            "declare void @llvm.masked.store.v1i{width}.p0v1i{width}(<1 x i{width}>, \
<1 x i{width}>*, i32, <1 x i1>)\n"
        ));
    }
    out.push('\n');
    out
}

pub(crate) fn llvm_memory_write(
    address: &str,
    value: &str,
    width: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) {
    let pointer = llvm_byte_pointer(address, width, word, body, counter);
    if width == word.bits {
        body.push_str(&format!(
            "  store {} {value}, {}* {pointer}, align 1\n",
            word.ty, word.ty
        ));
        return;
    }
    let narrowed = llvm_fresh(counter);
    body.push_str(&format!(
        "  {narrowed} = trunc {} {value} to i{width}\n",
        word.ty
    ));
    body.push_str(&format!(
        "  store i{width} {narrowed}, i{width}* {pointer}, align 1\n"
    ));
}

/// Address the flat byte buffer, then retype the pointer for a `width`-bit
/// access. Typed-pointer mode requires the pointee type to match the access,
/// so the byte offset and the access type are two separate steps.
/// The window translated code may address, as one module-level fact.
///
/// ⚠️ `memory_base` in the JIT contract was a PROMISE, not a bound: translated
/// code computed an address and used it, there is no call in the emitted bytes
/// to put a check in, and a host that named a buffer was answering for every
/// address the program could reach. It could not answer, twice in one day --
/// a stencilled `swp x0, x1, [sp]` took one harness down and a translated
/// store took another.
///
/// Every interpreter here already masks: the executors reach memory through a
/// host hook, and every host in this repository writes `buffer[(addr + i) &
/// MASK]`. Translated code did not, which is the whole of the difference. So
/// it masks too, with a value that arrives the way every other machine part
/// arrives -- patched in at translation time.
///
/// ⚠️ Defined here as all-ones and INTERNAL, so `emit-llvm-ir`'s consumers are
/// unchanged: masking by all-ones is the identity, and the optimiser folds the
/// load and the `and` away entirely. `emit-stencil-ll` rewrites this one line
/// to an external declaration, which is what turns it into a relocation -- and
/// a relocation named `AXIS_HOLE_..._mask` is a hole the patcher already knows
/// how to fill, by the naming rule the table reads: the tail says which
/// machine part, so `mask` needed one entry in one table rather than a new
/// kind of relocation.
pub(crate) const AXIS_MEMORY_MASK_DEFINITION: &str =
    "@AXIS_HOLE_memory_mask = internal global i64 -1\n\n";

/// The same symbol, as a stencil sees it: undefined, therefore relocated.
pub(crate) const AXIS_MEMORY_MASK_DECLARATION: &str =
    "@AXIS_HOLE_memory_mask = external dso_local global i64\n\n";

pub(crate) fn llvm_byte_pointer(
    address: &str,
    width: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    // ⚠️ Masked before it is used, and this is the only place that has to be
    // true: every load, store and atomic in every lowered handler forms its
    // pointer here. An address outside the window wraps to inside it, which is
    // exactly what the interpreters' host hooks do -- so the two engines agree
    // about a program that runs off the end instead of one of them dying.
    let held = llvm_fresh(counter);
    body.push_str(&format!(
        "  {held} = load i64, i64* @AXIS_HOLE_memory_mask\n"
    ));
    let window = llvm_fresh(counter);
    match word.bits {
        64 => body.push_str(&format!("  {window} = bitcast i64 {held} to i64\n")),
        bits if bits < 64 => body.push_str(&format!(
            "  {window} = trunc i64 {held} to {}\n",
            word.ty
        )),
        _ => body.push_str(&format!("  {window} = zext i64 {held} to {}\n", word.ty)),
    }
    let inside = llvm_fresh(counter);
    body.push_str(&format!(
        "  {inside} = and {} {address}, {window}\n",
        word.ty
    ));
    let byte_pointer = llvm_fresh(counter);
    body.push_str(&format!(
        "  {byte_pointer} = getelementptr i8, i8* %mem, {} {inside}\n",
        word.ty
    ));
    if width == 8 {
        return byte_pointer;
    }
    let typed = llvm_fresh(counter);
    body.push_str(&format!(
        "  {typed} = bitcast i8* {byte_pointer} to i{width}*\n"
    ));
    typed
}

/// Lower a guard to an `i1`. Equality leaves compose with `and`/`or`/`not`,
/// matching `c_guard_expr`.
pub(crate) fn llvm_guard(
    guard: &SemanticExpr,
    width: u32,
    word: Word,
    symbols: &[String],
    renames: &std::collections::HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<String> {
    let SemanticExpr::List(items) = guard else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
        let instruction = if op == "and" { "and" } else { "or" };
        let mut folded = llvm_guard(&items[1], width, word, symbols, renames, body, counter)?;
        for child in &items[2..] {
            let next = llvm_guard(child, width, word, symbols, renames, body, counter)?;
            let combined = llvm_fresh(counter);
            body.push_str(&format!(
                "  {combined} = {instruction} i1 {folded}, {next}\n"
            ));
            folded = combined;
        }
        return Some(folded);
    }
    if op == "not" && items.len() == 2 {
        let inner = llvm_guard(&items[1], width, word, symbols, renames, body, counter)?;
        let negated = llvm_fresh(counter);
        body.push_str(&format!("  {negated} = xor i1 {inner}, true\n"));
        return Some(negated);
    }
    if items.len() != 3 {
        return None;
    }
    let predicate = match op.as_str() {
        "icmp_eq" => "eq",
        "icmp_ne" => "ne",
        "icmp_slt" => "slt",
        "icmp_sge" => "sge",
        "icmp_ult" => "ult",
        "icmp_uge" => "uge",
        _ => return None,
    };
    let lhs = llvm_effect_expr(&items[1], width, word, symbols, renames, body, counter)?;
    let rhs = llvm_effect_expr(&items[2], width, word, symbols, renames, body, counter)?;
    let compared = llvm_fresh(counter);
    body.push_str(&format!(
        "  {compared} = icmp {predicate} {} {lhs}, {rhs}\n",
        word.ty
    ));
    Some(compared)
}

/// Lower a pure effect subexpression through the same typed IR the pure
/// functions use, so effect values and `axis_eval_*` bodies cannot disagree.
/// The value an effect writes: a memory read when the value is a `load`, and an
/// ordinary expression otherwise.
///
/// Split out because a lifted region needs exactly this and would otherwise
/// have to peel the load a second time -- and a second peeling is a second
/// place for the sign of a byte load to be wrong.
/// Everything an emitted module needs before its functions: the semantics
/// helpers at each width the document uses, the AArch64 helpers when it uses
/// them, and the float intrinsics when it needs those.
///
/// One function, because a lifted region needs exactly the same preamble as
/// `axis_semantics.ll` and getting it by copying was how the region module came
/// to call `@axis_a64_extend_reg` without defining it.
pub(crate) fn llvm_module_preamble(document: &Document) -> String {
    let mut out = String::new();
    out.push_str(&render_semantics_helpers(llvm_word(32)));
    // Wider preludes are the same template at another width, emitted only when
    // something needs them so narrower modules stay byte-identical.
    for width in wide_semantics_widths(document) {
        out.push_str(&render_semantics_helpers(llvm_word(width)));
    }
    // Description-defined functions, once per tier that can hold them; calls
    // to them stay calls (`Sem::Call`), so a body is emitted once however
    // often it is used.
    let mut tiers = vec![32];
    tiers.extend(wide_semantics_widths(document));
    for tier in tiers {
        let word = llvm_word(tier);
        let ty = word.ty;
        for function in &document.functions {
            let widest = function
                .params
                .iter()
                .map(|(_, width)| *width)
                .chain(std::iter::once(function.result_width))
                .max()
                .unwrap_or(32);
            if widest > tier {
                continue;
            }
            let Ok(sem) = lower(&function.body, function.result_width) else {
                continue;
            };
            let mut body = String::new();
            let mut counter = 0u32;
            let result = llvm_lower(&sem, word, &mut body, &mut counter);
            let ret = llvm_fresh(&mut counter);
            body.push_str(&format!(
                "  {ret} = call {ty} @{}mask({ty} {result}, {ty} {})\n",
                word.prefix, function.result_width
            ));
            let params: Vec<String> = function
                .params
                .iter()
                .map(|(name, _)| format!("{ty} %{}", python_ident(name)))
                .collect();
            out.push_str(&format!(
                "define internal {ty} @{}fn_{}({}) {{\nentry:\n{body}  ret {ty} {ret}\n}}\n\n",
                word.prefix,
                crate::emit::semantics::function_ident(&function.name),
                params.join(", ")
            ));
        }
    }
    // sqrt and fma are LLVM intrinsics rather than instructions, so they need
    // declaring. Emitted only when used, keeping other modules unchanged.
    if document_uses_a64_ops(document) {
        // The bitmask decode finds the highest set bit of a 7-bit field, which
        // is a count-leading-zeros away. The width prelude declares the same
        // intrinsic when a document counts leading zeros, and LLVM rejects a
        // second declaration of it.
        if !out.contains("declare i64 @llvm.ctlz.i64") {
            out.push_str("declare i64 @llvm.ctlz.i64(i64, i1)\n\n");
        }
        out.push_str(A64_HELPERS);
    }
    // A guarded store lowers to `llvm.masked.store`, which has to be declared.
    // Emitted only when the description has one, so a module without any is the
    // byte-identical artifact it was before.
    if document.instructions.iter().any(|instruction| {
        instruction.behavior.as_ref().is_some_and(|behavior| {
            behavior.effects.iter().any(|effect| {
                effect.guard.is_some()
                    && matches!(effect.loc, crate::effects::Loc::Mem { .. })
            })
        })
    }) {
        out.push_str(&llvm_masked_store_declarations());
    }
    if crate::emit::semantics::document_uses_float_ops(document) {
        out.push_str(
            "declare double @llvm.sqrt.f64(double)\n             declare float @llvm.sqrt.f32(float)\n             declare double @llvm.fma.f64(double, double, double)\n             declare float @llvm.fma.f32(float, float, float)\n             declare i32 @llvm.fptosi.sat.i32.f32(float)\n             declare i64 @llvm.fptosi.sat.i64.f32(float)\n             declare i32 @llvm.fptosi.sat.i32.f64(double)\n             declare i64 @llvm.fptosi.sat.i64.f64(double)\n             declare i32 @llvm.fptoui.sat.i32.f32(float)\n             declare i64 @llvm.fptoui.sat.i64.f32(float)\n             declare i32 @llvm.fptoui.sat.i32.f64(double)\n             declare i64 @llvm.fptoui.sat.i64.f64(double)\n",
        );
        // ⚠️ Half precision, and the 16-bit integers it converts to. The call
        // sites spell `@llvm.<op>.sat.i<width>.f<bits>` from whatever widths
        // the semantics name, and this block was written when those were only
        // ever 32 and 64: AArch64's FP16 `fcvtzs h` made the first
        // `fptosi.sat.i16.f16`, and every module containing it failed to parse.
        out.push_str("declare half @llvm.sqrt.f16(half)\ndeclare half @llvm.fma.f16(half, half, half)\n");
        for (width, float_bits) in [(16, 16), (32, 16), (64, 16), (16, 32), (16, 64)] {
            let float = if float_bits == 16 { "half" } else if float_bits == 32 { "float" } else { "double" };
            for op in ["fptosi", "fptoui"] {
                out.push_str(&format!("declare i{width} @llvm.{op}.sat.i{width}.f{float_bits}({float})\n"));
            }
        }
        out.push('\n');
    }
    out
}

/// The ordering an `atomic_load` states, as LLVM spells it.
///
/// `release` is absent on purpose: LLVM has no release load and neither does
/// any machine, so a description that asked for one would be asking for an
/// instruction that cannot be written. The parser rejects it rather than
/// letting it arrive here to be quietly downgraded to `monotonic`.
fn llvm_load_ordering(order: Option<&SemanticExpr>) -> Option<&'static str> {
    match order {
        Some(SemanticExpr::Atom(name)) if name == "acquire" => Some("acquire"),
        Some(SemanticExpr::Atom(name)) if name == "relaxed" => Some("monotonic"),
        _ => None,
    }
}

pub(crate) fn llvm_effect_value(
    effect: &crate::effects::Effect,
    out_width: u32,
    word: Word,
    symbols: &[String],
    renames: &std::collections::HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<String> {
    let ty = word.ty;
    match &effect.value.expr {
        SemanticExpr::List(items)
            if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
                && matches!(items.len(), 4 | 5) =>
        {
            let access = llvm_access_width(items.get(1)?)?;
            let signed = matches!(items.get(2), Some(SemanticExpr::Atom(sign)) if sign == "signed");
            let address = llvm_effect_expr(
                items.last()?,
                effect.value.load_address_width?,
                word,
                symbols,
                renames,
                body,
                counter,
            )?;
            // ⚠️ An atomic load read PLAINLY here, which is a different
            // instruction with the same answer on one thread and the wrong one
            // on any other. It was unreachable while every atomic shape was
            // refused before lowering, and became reachable the moment a lone
            // atomic access was allowed through. `(atomic_load ty sign order
            // addr)` states the order; `(load ty sign addr)` has none.
            let ordering = match &effect.value.expr {
                SemanticExpr::List(items) if effect.value.load_atomic => {
                    llvm_load_ordering(items.get(3))
                }
                _ => None,
            };
            let raw = match ordering {
                Some(order) => llvm_memory_read_atomic(
                    &address, access, word, order, body, counter,
                ),
                None => llvm_memory_read(&address, access, word, body, counter),
            };
            let helper = if signed { "sext" } else { "zext" };
            let extended = llvm_fresh(counter);
            body.push_str(&format!(
                "  {extended} = call {ty} @{}{helper}({ty} {raw}, {ty} {access}, {ty} {out_width})\n",
                word.prefix
            ));
            Some(extended)
        }
        expression => llvm_effect_expr(
            expression,
            effect.value.width,
            word,
            symbols,
            renames,
            body,
            counter,
        ),
    }
}

pub(crate) fn llvm_effect_expr(
    expr: &SemanticExpr,
    width: u32,
    word: Word,
    symbols: &[String],
    renames: &std::collections::HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<String> {
    // An AArch64 operator is not portable semantics, so it never reaches the
    // typed IR: each one is emitted as a call and replaced by the temp holding
    // its result, leaving an expression `lower` understands.
    if crate::effects::render_semexpr(expr).contains("(a64_") {
        let mut extended = symbols.to_vec();
        let hoisted = hoist_a64_ops(
            expr, width, word, &mut extended, renames, body, counter,
        )?;
        return llvm_effect_expr(&hoisted, width, word, &extended, renames, body, counter);
    }
    // `width` is the expression's own semantic width, which drives the masking
    // the helpers apply; `word` is the function's single host type, so a 32-bit
    // address computation inside a 64-bit effect function still yields an i64
    // temp the surrounding stores can use.
    let sem = lower(expr, width).ok()?;
    // Every symbol has to be something this ABI passes in. A value that reads
    // named architectural state -- AArch64's `adc`, whose carry-in comes from
    // `nzcv` -- otherwise lowers to a reference to an SSA value that was never
    // defined, and the module only fails at its consumer. Withholding it here
    // is the same rule the `Loc::State` check applies to state writes.
    // ⚠️ Plus whatever `renames` currently binds. Those are values THIS
    // instruction has already produced -- an earlier effect's write -- and a
    // later effect is entitled to read one. Checking against the input operands
    // alone refused `fls`, whose second effect NaN-boxes what its first effect
    // loaded: `rd` is an output, so it was not an allowed symbol, though the
    // temp holding it had just been emitted. Declaring `rd` `inout` would lower
    // but would also say the instruction reads the register's entry value,
    // which it does not.
    //
    // Sound because a name in `renames` is defined by construction: it maps to
    // an SSA temp this body already wrote. The order below still matters for
    // the reason it always did -- a renamed symbol is a temp and would not be
    // in the allowed set -- so the check happens before the rewrite.
    let allowed: Vec<String> = symbols
        .iter()
        .cloned()
        .chain(renames.keys().cloned())
        .collect();
    crate::ir::check_symbols(&sem, &allowed).ok()?;
    let sem = rename_symbols(&sem, renames);
    Some(llvm_lower(&sem, word, body, counter))
}

/// The symbols an effect function's body may reference: its input operands, plus
/// the `%pc` the ABI passes in (a branch target is `pc` plus a displacement).
fn effect_symbols(
    instruction: &crate::ast::Instruction,
    state_names: &[String],
) -> Vec<String> {
    instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| operand.name.clone())
        .chain(std::iter::once("pc".to_string()))
        .chain(state_names.iter().cloned())
        .collect()
}

/// Whether any of this behavior's expressions read a named piece of state.
fn behavior_mentions_state(behavior: &crate::effects::Behavior, name: &str) -> bool {
    behavior.effects.iter().any(|effect| {
        let mentions = |expr: &SemanticExpr| {
            crate::effects::render_semexpr(expr)
                .split(|c: char| !c.is_alphanumeric() && c != '_')
                .any(|token| token == name)
        };
        mentions(&effect.value.expr)
            || effect.guard.as_ref().is_some_and(|guard| mentions(&guard.expr))
            || matches!(&effect.loc, crate::effects::Loc::Mem { addr, .. } if mentions(&addr.expr))
    })
}

fn llvm_access_width(atom: &SemanticExpr) -> Option<u32> {
    let SemanticExpr::Atom(text) = atom else {
        return None;
    };
    let width: u32 = text.strip_prefix('i')?.parse().ok()?;
    matches!(width, 8 | 16 | 32 | 64).then_some(width)
}

/// The same, for the limb-splitting paths: an access that is a whole number of
/// slots is legal there because it is emitted as that many accesses. Kept apart
/// from `llvm_access_width` so the single-access paths, where a 128-bit `load`
/// has no instruction to lower to, still refuse it.
pub(crate) fn llvm_limb_access_width(atom: &SemanticExpr, word: Word) -> Option<u32> {
    if let Some(width) = llvm_access_width(atom) {
        return Some(width);
    }
    let SemanticExpr::Atom(text) = atom else {
        return None;
    };
    let width: u32 = text.strip_prefix('i')?.parse().ok()?;
    (width > word.bits && width % word.bits == 0).then_some(width)
}

/// Lower a conversion. Float-to-integer uses LLVM's *saturating* intrinsics,
/// whose documented behaviour — clamp to the range, NaN to zero — is exactly
/// the rule AXIS specifies, so no explicit range test is needed. The plain
/// `fptosi`/`fptoui` instructions are poison out of range and would have been
/// the wrong choice.
fn llvm_convert(
    op: Op,
    value: String,
    from_bits: u32,
    width: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let ty = word.ty;
    let float_of = |bits: u32| llvm_float(bits).0;
    let canonical_of = |bits: u32| llvm_float(bits).1;
    let bitcast_to_float = |value: &str, bits: u32, body: &mut String, counter: &mut u32| {
        // A narrower float sits in the low bits of the evaluation type, so it
        // is truncated to its own width before being reinterpreted.
        let narrowed = if bits < word.bits {
            let t = llvm_fresh(counter);
            body.push_str(&format!("  {t} = trunc {ty} {value} to i{bits}\n"));
            t
        } else {
            value.to_string()
        };
        let cast = llvm_fresh(counter);
        body.push_str(&format!(
            "  {cast} = bitcast i{bits} {narrowed} to {}\n",
            float_of(bits)
        ));
        cast
    };
    let float_to_bits = |value: &str, bits: u32, body: &mut String, counter: &mut u32| {
        let raw = llvm_fresh(counter);
        body.push_str(&format!(
            "  {raw} = bitcast {} {value} to i{bits}\n",
            float_of(bits)
        ));
        let unordered = llvm_fresh(counter);
        body.push_str(&format!(
            "  {unordered} = fcmp uno {} {value}, {value}\n",
            float_of(bits)
        ));
        let canonical = llvm_fresh(counter);
        body.push_str(&format!(
            "  {canonical} = select i1 {unordered}, i{bits} {}, i{bits} {raw}\n",
            canonical_of(bits)
        ));
        if bits < word.bits {
            let widened = llvm_fresh(counter);
            body.push_str(&format!("  {widened} = zext i{bits} {canonical} to {ty}\n"));
            widened
        } else {
            canonical
        }
    };
    match op {
        Op::FcvtF2S | Op::FcvtF2U => {
            let float = bitcast_to_float(&value, from_bits, body, counter);
            let intrinsic = if matches!(op, Op::FcvtF2S) {
                "fptosi"
            } else {
                "fptoui"
            };
            let converted = llvm_fresh(counter);
            body.push_str(&format!(
                "  {converted} = call i{width} @llvm.{intrinsic}.sat.i{width}.f{from_bits}({} {float})\n",
                float_of(from_bits)
            ));
            if width < word.bits {
                let widened = llvm_fresh(counter);
                body.push_str(&format!("  {widened} = zext i{width} {converted} to {ty}\n"));
                widened
            } else {
                converted
            }
        }
        Op::FcvtS2F | Op::FcvtU2F => {
            let signed = matches!(op, Op::FcvtS2F);
            // ⚠️ From the SOURCE's width, not the word's. The integer is the
            // low `from_bits` of the value either way, so the result is the
            // same -- but from a 128-bit word, converting to half becomes a
            // call to compiler-rt's `__floattihf`, which the platform runtime
            // does not ship, and AArch64's FP16 SCVTF would not link.
            let (source, source_ty) = if from_bits < word.bits {
                let narrowed = llvm_fresh(counter);
                body.push_str(&format!("  {narrowed} = trunc {ty} {value} to i{from_bits}\n"));
                (narrowed, format!("i{from_bits}"))
            } else {
                (value.clone(), ty.to_string())
            };
            let instruction = if signed { "sitofp" } else { "uitofp" };
            let converted = llvm_fresh(counter);
            body.push_str(&format!(
                "  {converted} = {instruction} {source_ty} {source} to {}\n",
                float_of(width)
            ));
            float_to_bits(&converted, width, body, counter)
        }
        Op::FcvtF2F => {
            let float = bitcast_to_float(&value, from_bits, body, counter);
            let instruction = if width > from_bits { "fpext" } else { "fptrunc" };
            let converted = llvm_fresh(counter);
            body.push_str(&format!(
                "  {converted} = {instruction} {} {float} to {}\n",
                float_of(from_bits),
                float_of(width)
            ));
            float_to_bits(&converted, width, body, counter)
        }
        _ => unreachable!("not a conversion"),
    }
}

/// Reinterpret a value held in the function's evaluation word as a float,
/// narrowing first when the word is wider than the float.
///
/// A float operator's width is its own, not the function's. Stage F2 puts an
/// `f32` operator inside a 64-bit lane register's word — each lane of `v2f32` is
/// The integer width a float type bitcasts through.
///
/// ⚠️ Derived from the TYPE rather than assumed. This was `if float_ty ==
/// "double" { 64 } else { 32 }`, which is right for exactly two types and made
/// `half` bitcast through `i32` -- rejected by LLVM outright, which is the
/// better half of how this kind of assumption fails.
fn llvm_float_bits(float_ty: &str) -> u32 {
    match float_ty {
        "double" => 64,
        "float" => 32,
        "half" => 16,
        other => unreachable!("no width for LLVM float type `{other}`"),
    }
}

/// How a float format appears in LLVM IR: its type name, its canonical NaN as
/// the decimal an `i<bits>` literal takes, and the suffix an intrinsic name
/// spells it with (`llvm.sqrt.f64`).
///
/// The one place this backend decides what a float is. It was four -- two
/// `if bits > 32 { "double" }` and two more beside the NaN patterns -- which is
/// how `ir::FLOAT_FORMATS` came to exist; the architectural facts live there
/// and this renders them.
fn llvm_float(bits: u32) -> (&'static str, &'static str, String) {
    let format = crate::ir::float_format(bits)
        .unwrap_or_else(|| unreachable!("float format {bits} reached the LLVM emitter"));
    let ty = match format.name {
        "f64" => "double",
        "f32" => "float",
        "f16" => "half",
        other => unreachable!("no LLVM type for float format `{other}`"),
    };
    let canonical: &'static str = match format.name {
        "f64" => "9221120237041090560",
        "f32" => "2143289344",
        "f16" => "32256",
        other => unreachable!("no LLVM canonical NaN for float format `{other}`"),
    };
    (ty, canonical, format!("f{}", format.bits))
}

/// handed to `fadd f32` — and `bitcast i64 to float` is not a cast LLVM has. The
/// scalar float corpus never produced this because a 32-bit float instruction
/// has 32-bit operands, so its word was 32 too.
fn llvm_to_float(
    value: &str,
    word: Word,
    float_ty: &str,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let bits = llvm_float_bits(float_ty);
    let narrowed = if word.bits == bits {
        value.to_string()
    } else {
        let temp = llvm_fresh(counter);
        body.push_str(&format!(
            "  {temp} = trunc {} {value} to i{bits}\n",
            word.ty
        ));
        temp
    };
    let cast = llvm_fresh(counter);
    body.push_str(&format!(
        "  {cast} = bitcast i{bits} {narrowed} to {float_ty}\n"
    ));
    cast
}

/// The reverse: a float's bit pattern, widened back into the function's word.
fn llvm_from_float(
    value: &str,
    word: Word,
    float_ty: &str,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let bits = llvm_float_bits(float_ty);
    let pattern = llvm_fresh(counter);
    body.push_str(&format!(
        "  {pattern} = bitcast {float_ty} {value} to i{bits}\n"
    ));
    if word.bits == bits {
        return pattern;
    }
    let widened = llvm_fresh(counter);
    body.push_str(&format!(
        "  {widened} = zext i{bits} {pattern} to {}\n",
        word.ty
    ));
    widened
}

pub(crate) fn llvm_fresh(counter: &mut u32) -> String {
    let id = format!("%t{counter}");
    *counter += 1;
    id
}

/// Lower a `Sem` node to an LLVM operand string, appending any instructions it
/// needs to `body`. Arithmetic ops become native SSA instructions (folded
/// left-associatively, matching the C interpreter's full-width arithmetic);
/// width-sensitive ops become calls to the `axis_sem_*` prelude helpers.
fn llvm_lower(sem: &Sem, word: Word, body: &mut String, counter: &mut u32) -> String {
    // ⚠️ SHARED, not re-emitted. The IR inlines every `let` and every helper
    // argument by copying the tree, so a value named three times is three
    // subtrees -- and nested, that multiplies: AArch64's FP16 reductions came
    // to 587,267 lines of IR, and clang did not finish them in twenty hours.
    // LLVM is SSA, so a subtree already lowered in this expression is its
    // value, and is reused by structural identity. The cache lives for one
    // top-level call, whose output is straight-line: a value defined there
    // dominates every later use in it, which would not hold across the
    // guarded blocks an effect function builds between calls.
    thread_local! {
        static SEEN: std::cell::RefCell<(u32, std::collections::HashMap<Sem, String>)> =
            std::cell::RefCell::new((0, std::collections::HashMap::new()));
    }
    if let Some(done) = SEEN.with(|seen| seen.borrow().1.get(sem).cloned()) {
        return done;
    }
    SEEN.with(|seen| seen.borrow_mut().0 += 1);
    let value = llvm_lower_once(sem, word, body, counter);
    SEEN.with(|seen| {
        let mut seen = seen.borrow_mut();
        seen.0 -= 1;
        if seen.0 == 0 {
            seen.1.clear();
        } else {
            seen.1.insert(sem.clone(), value.clone());
        }
    });
    value
}

fn llvm_lower_once(sem: &Sem, word: Word, body: &mut String, counter: &mut u32) -> String {
    let ty = word.ty;
    let sem_helper = |name: &str| format!("{}{name}", word.prefix);
    match sem {
        Sem::Sym(name) => format!("%{}", python_ident(name)),
        Sem::Call { name, args, .. } => {
            let mut values = Vec::new();
            for (param, arg) in args {
                let value = llvm_lower(arg, word, body, counter);
                let masked = llvm_call(&sem_helper("mask"), &format!("{value}, {ty} {param}"), word, body, counter);
                values.push(format!("{ty} {masked}"));
            }
            let t = llvm_fresh(counter);
            body.push_str(&format!(
                "  {t} = call {ty} @{}fn_{}({})\n",
                word.prefix,
                crate::emit::semantics::function_ident(name),
                values.join(", ")
            ));
            t
        }
        // The C interpreter masks the final result, so intermediate constants
        // only need their low `word` bits; emit them as the signed bit pattern
        // of that width, which is how LLVM spells integer literals.
        Sem::Int { value, .. } => match word.bits {
            128 => format!("{}", *value as i128),
            64 => format!("{}", *value as u64 as i64),
            _ => format!("{}", *value as u32 as i32),
        },
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => {
            let value = llvm_lower(arg, word, body, counter);
            if crate::ir::is_float_op(*op) {
                return llvm_convert(*op, value, *from_bits, *width, word, body, counter);
            }
            let helper = sem_helper(if matches!(op, Op::Sext) { "sext" } else { "zext" });
            let t = llvm_fresh(counter);
            body.push_str(&format!(
                "  {t} = call {ty} @{helper}({ty} {value}, {ty} {from_bits}, {ty} {width})\n"
            ));
            t
        }
        Sem::App { op, width, args } => {
            let width = *width;
            let a: Vec<String> = args
                .iter()
                .map(|arg| llvm_lower(arg, word, body, counter))
                .collect();
            match op {
                // LLVM makes a shift at or past the width *poison*, unlike
                // SMT-LIB's zero and C's undefined, so the count is clamped to
                // something the shift accepts and the saturating answer is
                // selected in beside it. Clamped rather than left to the
                // unselected arm: `select` chooses a value, and building a
                // poison one to discard is a hazard the optimizer is entitled
                // to act on.
                Op::Ones => match a.first() {
                    None => format!("-1"),
                    Some(count) => {
                        // The count is evaluated at the node's width, so it is
                        // narrowed to that width before anything reads it --
                        // SMT-LIB resizes to the node's sort and cannot do
                        // otherwise, and the five backends agree or they are
                        // not describing one machine.
                        let count = if width < word.bits {
                            let narrowed = llvm_fresh(counter);
                            body.push_str(&format!(
                                "  {narrowed} = and {ty} {count}, {}\n",
                                (1u128 << width) - 1
                            ));
                            narrowed
                        } else {
                            count.clone()
                        };
                        let big = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {big} = icmp uge {ty} {count}, {width}\n"
                        ));
                        let safe = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {safe} = select i1 {big}, {ty} 0, {ty} {count}\n"
                        ));
                        let shifted = llvm_fresh(counter);
                        body.push_str(&format!("  {shifted} = shl {ty} 1, {safe}\n"));
                        let mask = llvm_fresh(counter);
                        body.push_str(&format!("  {mask} = sub {ty} {shifted}, 1\n"));
                        let all = if width >= word.bits {
                            "-1".to_string()
                        } else {
                            format!("{}", (1u128 << width) - 1)
                        };
                        let result = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {result} = select i1 {big}, {ty} {all}, {ty} {mask}\n"
                        ));
                        result
                    }
                },
                Op::Zeros => "0".to_string(),
                Op::Add => llvm_fold("add", &a, word, body, counter),
                Op::Sub => llvm_fold("sub", &a, word, body, counter),
                Op::Mul => llvm_fold("mul", &a, word, body, counter),
                Op::Udiv => llvm_call(
                    &sem_helper("udiv"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::Sdiv => llvm_call(
                    &sem_helper("sdiv"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::Urem => llvm_call(
                    &sem_helper("urem"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::Srem => llvm_call(
                    &sem_helper("srem"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::And => llvm_fold("and", &a, word, body, counter),
                Op::Or => llvm_fold("or", &a, word, body, counter),
                Op::Xor => llvm_fold("xor", &a, word, body, counter),
                // The amount is read at the node's width, matching the other
                // backends and SMT-LIB, which resizes it to the operand's sort
                // and has no other option.
                Op::Shl => {
                    let amount = llvm_shift_amount(&a[1], width, word, body, counter);
                    llvm_call(
                        &sem_helper("shl"),
                        &format!("{}, {ty} {amount}", a[0]),
                        word,
                        body,
                        counter,
                    )
                }
                Op::Lshr => {
                    let amount = llvm_shift_amount(&a[1], width, word, body, counter);
                    llvm_call(
                        &sem_helper("lshr"),
                        &format!("{}, {ty} {amount}, {ty} {width}", a[0]),
                        word,
                        body,
                        counter,
                    )
                }
                Op::Ashr => {
                    let amount = llvm_shift_amount(&a[1], width, word, body, counter);
                    llvm_call(
                        &sem_helper("sra"),
                        &format!("{}, {ty} {amount}, {ty} {width}", a[0]),
                        word,
                        body,
                        counter,
                    )
                }
                Op::Not => llvm_call(
                    &sem_helper("not"),
                    &format!("{}, {ty} {width}", a[0]),
                    word,
                    body,
                    counter,
                ),
                Op::Rol => llvm_call(
                    &sem_helper("rotl"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::Ror => llvm_call(
                    &sem_helper("rotr"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::Clz => llvm_call(
                    &sem_helper("clz"),
                    &format!("{}, {ty} {width}", a[0]),
                    word,
                    body,
                    counter,
                ),
                Op::Ctz => llvm_call(
                    &sem_helper("ctz"),
                    &format!("{}, {ty} {width}", a[0]),
                    word,
                    body,
                    counter,
                ),
                Op::Cpop => llvm_call(
                    &sem_helper("cpop"),
                    &format!("{}, {ty} {width}", a[0]),
                    word,
                    body,
                    counter,
                ),
                Op::MinS => llvm_call(
                    &sem_helper("min_s"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::MaxS => llvm_call(
                    &sem_helper("max_s"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::MinU => llvm_call(
                    &sem_helper("min_u"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                Op::MaxU => llvm_call(
                    &sem_helper("max_u"),
                    &format!("{}, {ty} {}, {ty} {width}", a[0], a[1]),
                    word,
                    body,
                    counter,
                ),
                // IEEE-754: bitcast into the float domain, compute natively,
                // then replace a NaN result with AXIS's canonical quiet NaN so
                // the bit pattern matches the other backends on any host.
                // The whole point of the operator: the widening happens here,
                // inside a function whose evaluation width is the narrow one.
                Op::Mulh | Op::Mulhu | Op::Mulhsu => {
                    // Twice the operator's width, but never narrower than the
                    // evaluation word the operands sit in: an 8-bit high half
                    // (SVE2's SMULH.B) in a 32-bit word would otherwise "extend"
                    // i32 to i16, which is not a cast LLVM has.
                    let word_bits: u32 = ty.trim_start_matches('i').parse().unwrap_or(width * 2);
                    let wide_bits = (width * 2).max(word_bits);
                    let wide = format!("i{wide_bits}");
                    let extend = |value: &str, signed: bool, body: &mut String, counter: &mut u32| {
                        // The operand sits in the evaluation word, so it is first
                        // reduced to its own width and then extended to double.
                        let narrowed = llvm_call(
                            &sem_helper(if signed { "signext" } else { "mask" }),
                            &format!("{value}, {ty} {width}"),
                            word,
                            body,
                            counter,
                        );
                        if wide_bits == word_bits {
                            return narrowed; // already extended within the word
                        }
                        let temp = llvm_fresh(counter);
                        let how = if signed { "sext" } else { "zext" };
                        body.push_str(&format!(
                            "  {temp} = {how} {ty} {narrowed} to {wide}\n"
                        ));
                        temp
                    };
                    let (lhs_signed, rhs_signed) = match op {
                        Op::Mulh => (true, true),
                        Op::Mulhu => (false, false),
                        _ => (true, false),
                    };
                    let lhs = extend(&a[0], lhs_signed, body, counter);
                    let rhs = extend(&a[1], rhs_signed, body, counter);
                    let product = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {product} = mul {wide} {lhs}, {rhs}\n"
                    ));
                    let high = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {high} = lshr {wide} {product}, {width}\n"
                    ));
                    if wide_bits == word_bits {
                        // The caller masks to the operator's width, as it
                        // does every result.
                        high
                    } else {
                        let narrowed = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {narrowed} = trunc {wide} {high} to {ty}\n"
                        ));
                        narrowed
                    }
                }
                Op::IcmpEq | Op::IcmpNe | Op::IcmpSlt | Op::IcmpSge
                | Op::IcmpUlt | Op::IcmpUge => {
                    let predicate = match op {
                        Op::IcmpEq => "eq",
                        Op::IcmpNe => "ne",
                        Op::IcmpSlt => "slt",
                        Op::IcmpSge => "sge",
                        Op::IcmpUlt => "ult",
                        _ => "uge",
                    };
                    // The signed forms compare at the operator's own width, so a
                    // narrower value is sign-extended into the evaluation word
                    // first — otherwise a negative 12-bit immediate sitting in a
                    // 32-bit word would read as a large positive.
                    let side = |value: &str, body: &mut String, counter: &mut u32| {
                        // Signed forms sign-extend from the operator's width;
                        // the rest mask to it. Either way the comparison happens
                        // at the operator's width and not the function's — RV64's
                        // DIVW compares its divisor at i32, and divides by zero
                        // exactly when those 32 bits are zero.
                        let helper = if matches!(op, Op::IcmpSlt | Op::IcmpSge) {
                            "signext"
                        } else {
                            "mask"
                        };
                        llvm_call(
                            &sem_helper(helper),
                            &format!("{value}, {ty} {width}"),
                            word,
                            body,
                            counter,
                        )
                    };
                    let lhs = side(&a[0], body, counter);
                    let rhs = side(&a[1], body, counter);
                    let compared = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {compared} = icmp {predicate} {ty} {lhs}, {rhs}\n"
                    ));
                    let widened = llvm_fresh(counter);
                    body.push_str(&format!("  {widened} = zext i1 {compared} to {ty}\n"));
                    widened
                }
                Op::FcmpOeq | Op::FcmpOlt | Op::FcmpOle | Op::FcmpUno => {
                    let float_ty = llvm_float(width).0;
                    // LLVM's ordered predicates are already false for NaN and
                    // treat -0.0 as equal to +0.0, so these map directly; the
                    // i1 result is widened to the value width.
                    let predicate = match op {
                        Op::FcmpOeq => "oeq",
                        Op::FcmpOlt => "olt",
                        Op::FcmpOle => "ole",
                        _ => "uno",
                    };
                    let lhs = llvm_to_float(&a[0], word, float_ty, body, counter);
                    let rhs = llvm_to_float(&a[1], word, float_ty, body, counter);
                    let compared = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {compared} = fcmp {predicate} {float_ty} {lhs}, {rhs}\n"
                    ));
                    let widened = llvm_fresh(counter);
                    body.push_str(&format!("  {widened} = zext i1 {compared} to {ty}\n"));
                    widened
                }
                Op::Fneg => {
                    // LLVM has `fneg` as an instruction of its own, and like
                    // this operator it is the sign bit flipped and nothing
                    // else. It is deliberately *not* followed by the NaN
                    // canonicalisation the arithmetic above does: negating a
                    // NaN gives that NaN with its sign flipped, and replacing
                    // it with the canonical one would be a different function.
                    let float_ty = llvm_float(width).0;
                    let value = llvm_to_float(&a[0], word, float_ty, body, counter);
                    let negated = llvm_fresh(counter);
                    body.push_str(&format!("  {negated} = fneg {float_ty} {value}\n"));
                    llvm_from_float(&negated, word, float_ty, body, counter)
                }
                Op::Fsqrt | Op::Fma => {
                    let (float_ty, canonical, suffix) = llvm_float(width);
                    let intrinsic = if matches!(op, Op::Fsqrt) { "sqrt" } else { "fma" };
                    let cast = |value: &str, body: &mut String, counter: &mut u32| {
                        let t = llvm_to_float(value, word, float_ty, body, counter);
                        t
                    };
                    let operands: Vec<String> = a
                        .iter()
                        .map(|value| {
                            let temp = cast(value, body, counter);
                            format!("{float_ty} {temp}")
                        })
                        .collect();
                    let computed = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {computed} = call {float_ty} @llvm.{intrinsic}.{suffix}({})\n",
                        operands.join(", ")
                    ));
                    let bits = llvm_from_float(&computed, word, float_ty, body, counter);
                    let unordered = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {unordered} = fcmp uno {float_ty} {computed}, {computed}\n"
                    ));
                    let selected = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {selected} = select i1 {unordered}, {ty} {canonical}, {ty} {bits}\n"
                    ));
                    selected
                }
                // Declined before lowering: see the guard in the caller.
                Op::FaddRm | Op::FsubRm | Op::FmulRm | Op::FdivRm | Op::FsqrtRm
                | Op::FmaRm => {
                    unreachable!("directed rounding is declined before lowering")
                }
                Op::FaddFx | Op::FsubFx | Op::FmulFx | Op::FdivFx | Op::FsqrtFx
                | Op::FmaFx => {
                    unreachable!("floating-point exceptions are declined before lowering")
                }
                Op::FcvtF2SFx
                | Op::FcvtF2UFx
                | Op::FcvtS2FFx
                | Op::FcvtU2FFx
                | Op::FcvtF2FFx => {
                    unreachable!("conversion exceptions are Sem::Ext")
                }
                Op::Fadd | Op::Fsub | Op::Fmul | Op::Fdiv => {
                    let (float_ty, canonical, _) = llvm_float(width);
                    let instruction = match op {
                        Op::Fadd => "fadd",
                        Op::Fsub => "fsub",
                        Op::Fmul => "fmul",
                        _ => "fdiv",
                    };
                    let mut folded = llvm_to_float(&a[0], word, float_ty, body, counter);
                    for rhs in &a[1..] {
                        let cast = llvm_to_float(rhs, word, float_ty, body, counter);
                        let computed = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {computed} = {instruction} {float_ty} {folded}, {cast}\n"
                        ));
                        folded = computed;
                    }
                    let bits = llvm_from_float(&folded, word, float_ty, body, counter);
                    let unordered = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {unordered} = fcmp uno {float_ty} {folded}, {folded}\n"
                    ));
                    let selected = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {selected} = select i1 {unordered}, {ty} {canonical}, {ty} {bits}\n"
                    ));
                    selected
                }
                Op::FcvtF2S | Op::FcvtF2U | Op::FcvtS2F | Op::FcvtU2F | Op::FcvtF2F => {
                    unreachable!("conversions are Sem::Ext")
                }
                Op::Select => {
                    let condition = llvm_fresh(counter);
                    body.push_str(&format!("  {condition} = icmp ne {ty} {}, 0\n", a[0]));
                    let selected = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {selected} = select i1 {condition}, {ty} {}, {ty} {}\n",
                        a[1], a[2]
                    ));
                    selected
                }
                Op::Sext | Op::Zext => unreachable!("extends are Sem::Ext"),
            }
        }
    }
}

/// Fold `args` left-associatively with an LLVM binary instruction, matching the
/// C interpreter's full-width arithmetic. Returns the final operand.
fn llvm_fold(
    instr: &str,
    args: &[String],
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let ty = word.ty;
    let mut acc = args[0].clone();
    for rhs in &args[1..] {
        let t = llvm_fresh(counter);
        body.push_str(&format!("  {t} = {instr} {ty} {acc}, {rhs}\n"));
        acc = t;
    }
    acc
}

/// Emit a `call` to an `axis_sem_*` prelude helper and return its result temp.
/// `call_args` is the argument list after the leading value operand's type.
fn llvm_call(
    helper: &str,
    call_args: &str,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let ty = word.ty;
    let t = llvm_fresh(counter);
    body.push_str(&format!("  {t} = call {ty} @{helper}({ty} {call_args})\n"));
    t
}

/// LLVM IR port of `C_SEMANTICS_HELPERS`. Every helper computes on i32 host
/// values with the same masking/saturation discipline as the C interpreter, so
/// the two are bit-identical for widths up to 32. `signext` sign-extends a
/// `w`-bit value within i32 (used by the signed comparisons and `sra`).
/// Template for the semantics helper prelude. Every width-derived value is
/// a named placeholder -- `{ty}` the evaluation type, `{w}` the word width,
/// `{wm1}` the shift-amount mask, `{imin}` the most negative value -- so
/// rendering it at another width cannot miss one. Writing the 64-bit prelude
/// as a text substitution over the 32-bit one did miss `and i32 %a, 31`,
/// which silently masked 64-bit shift amounts to 5 bits.
const LLVM_SEMANTICS_TEMPLATE: &str = r#"declare {ty} @llvm.ctlz.{ty}({ty}, i1)
declare {ty} @llvm.cttz.{ty}({ty}, i1)
declare {ty} @llvm.ctpop.{ty}({ty})

define internal {ty} @{prefix}mask({ty} %v, {ty} %w) {
entry:
  %ge = icmp uge {ty} %w, {w}
  br i1 %ge, label %full, label %part
full:
  ret {ty} %v
part:
  %one = shl {ty} 1, %w
  %m = sub {ty} %one, 1
  %r = and {ty} %v, %m
  ret {ty} %r
}

define internal {ty} @{prefix}signext({ty} %v, {ty} %w) {
entry:
  %bad = icmp uge {ty} %w, {w}
  %zero = icmp eq {ty} %w, 0
  %skip = or i1 %bad, %zero
  br i1 %skip, label %keep, label %do
do:
  %sh = sub {ty} {w}, %w
  %l = shl {ty} %v, %sh
  %r = ashr {ty} %l, %sh
  ret {ty} %r
keep:
  ret {ty} %v
}

define internal {ty} @{prefix}udiv({ty} %a0, {ty} %b0, {ty} %w) {
entry:
  %a = call {ty} @{prefix}mask({ty} %a0, {ty} %w)
  %b = call {ty} @{prefix}mask({ty} %b0, {ty} %w)
  %zero = icmp eq {ty} %b, 0
  %safe_b = select i1 %zero, {ty} 1, {ty} %b
  %q = udiv {ty} %a, %safe_b
  %r = select i1 %zero, {ty} 0, {ty} %q
  ret {ty} %r
}

define internal {ty} @{prefix}sdiv({ty} %a0, {ty} %b0, {ty} %w) {
entry:
  %a = call {ty} @{prefix}signext({ty} %a0, {ty} %w)
  %b = call {ty} @{prefix}signext({ty} %b0, {ty} %w)
  %zero = icmp eq {ty} %b, 0
  %min = icmp eq {ty} %a, {imin}
  %neg_one = icmp eq {ty} %b, -1
  %overflow = and i1 %min, %neg_one
  %unsafe = or i1 %zero, %overflow
  %safe_a = select i1 %overflow, {ty} 0, {ty} %a
  %safe_b = select i1 %unsafe, {ty} 1, {ty} %b
  %q = sdiv {ty} %safe_a, %safe_b
  %overflow_result = select i1 %overflow, {ty} %a, {ty} %q
  %r = select i1 %zero, {ty} 0, {ty} %overflow_result
  ret {ty} %r
}

define internal {ty} @{prefix}shl({ty} %v, {ty} %a) {
entry:
  %ge = icmp uge {ty} %a, {w}
  %am = and {ty} %a, {wm1}
  %sh = shl {ty} %v, %am
  %r = select i1 %ge, {ty} 0, {ty} %sh
  ret {ty} %r
}

define internal {ty} @{prefix}lshr({ty} %v, {ty} %a, {ty} %w) {
entry:
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %ge = icmp uge {ty} %a, {w}
  %am = and {ty} %a, {wm1}
  %sh = lshr {ty} %m, %am
  %r = select i1 %ge, {ty} 0, {ty} %sh
  ret {ty} %r
}

define internal {ty} @{prefix}sra({ty} %v, {ty} %a, {ty} %w) {
entry:
  %s = call {ty} @{prefix}signext({ty} %v, {ty} %w)
  %ge = icmp uge {ty} %a, {wm1}
  %am = select i1 %ge, {ty} {wm1}, {ty} %a
  %sh = ashr {ty} %s, %am
  %r = call {ty} @{prefix}mask({ty} %sh, {ty} %w)
  ret {ty} %r
}

define internal {ty} @{prefix}not({ty} %v, {ty} %w) {
entry:
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %n = xor {ty} %m, -1
  %r = call {ty} @{prefix}mask({ty} %n, {ty} %w)
  ret {ty} %r
}

define internal {ty} @{prefix}rotl({ty} %v, {ty} %a0, {ty} %w) {
entry:
  %w0 = icmp eq {ty} %w, 0
  br i1 %w0, label %retv, label %go
go:
  %a = urem {ty} %a0, %w
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %az = icmp eq {ty} %a, 0
  br i1 %az, label %retm, label %rot
rot:
  %l = shl {ty} %m, %a
  %wa = sub {ty} %w, %a
  %rs = lshr {ty} %m, %wa
  %o = or {ty} %l, %rs
  %r = call {ty} @{prefix}mask({ty} %o, {ty} %w)
  ret {ty} %r
retm:
  ret {ty} %m
retv:
  ret {ty} %v
}

define internal {ty} @{prefix}rotr({ty} %v, {ty} %a, {ty} %w) {
entry:
  %w0 = icmp eq {ty} %w, 0
  br i1 %w0, label %retv, label %go
go:
  %am = urem {ty} %a, %w
  %d = sub {ty} %w, %am
  %r = call {ty} @{prefix}rotl({ty} %v, {ty} %d, {ty} %w)
  ret {ty} %r
retv:
  ret {ty} %v
}

define internal {ty} @{prefix}clz({ty} %v, {ty} %w) {
entry:
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %c = call {ty} @llvm.ctlz.{ty}({ty} %m, i1 false)
  %d = sub {ty} {w}, %w
  %r = sub {ty} %c, %d
  ret {ty} %r
}

define internal {ty} @{prefix}ctz({ty} %v, {ty} %w) {
entry:
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %z = icmp eq {ty} %m, 0
  %c = call {ty} @llvm.cttz.{ty}({ty} %m, i1 false)
  %r = select i1 %z, {ty} %w, {ty} %c
  ret {ty} %r
}

define internal {ty} @{prefix}cpop({ty} %v, {ty} %w) {
entry:
  %m = call {ty} @{prefix}mask({ty} %v, {ty} %w)
  %r = call {ty} @llvm.ctpop.{ty}({ty} %m)
  ret {ty} %r
}

define internal {ty} @{prefix}min_s({ty} %a, {ty} %b, {ty} %w) {
entry:
  %sa = call {ty} @{prefix}signext({ty} %a, {ty} %w)
  %sb = call {ty} @{prefix}signext({ty} %b, {ty} %w)
  %lt = icmp slt {ty} %sa, %sb
  %ma = call {ty} @{prefix}mask({ty} %a, {ty} %w)
  %mb = call {ty} @{prefix}mask({ty} %b, {ty} %w)
  %r = select i1 %lt, {ty} %ma, {ty} %mb
  ret {ty} %r
}

define internal {ty} @{prefix}max_s({ty} %a, {ty} %b, {ty} %w) {
entry:
  %sa = call {ty} @{prefix}signext({ty} %a, {ty} %w)
  %sb = call {ty} @{prefix}signext({ty} %b, {ty} %w)
  %gt = icmp sgt {ty} %sa, %sb
  %ma = call {ty} @{prefix}mask({ty} %a, {ty} %w)
  %mb = call {ty} @{prefix}mask({ty} %b, {ty} %w)
  %r = select i1 %gt, {ty} %ma, {ty} %mb
  ret {ty} %r
}

define internal {ty} @{prefix}min_u({ty} %a, {ty} %b, {ty} %w) {
entry:
  %ma = call {ty} @{prefix}mask({ty} %a, {ty} %w)
  %mb = call {ty} @{prefix}mask({ty} %b, {ty} %w)
  %lt = icmp ult {ty} %ma, %mb
  %r = select i1 %lt, {ty} %ma, {ty} %mb
  ret {ty} %r
}

define internal {ty} @{prefix}max_u({ty} %a, {ty} %b, {ty} %w) {
entry:
  %ma = call {ty} @{prefix}mask({ty} %a, {ty} %w)
  %mb = call {ty} @{prefix}mask({ty} %b, {ty} %w)
  %gt = icmp ugt {ty} %ma, %mb
  %r = select i1 %gt, {ty} %ma, {ty} %mb
  ret {ty} %r
}

define internal {ty} @{prefix}sext({ty} %v, {ty} %f, {ty} %w) {
entry:
  %s = call {ty} @{prefix}signext({ty} %v, {ty} %f)
  %r = call {ty} @{prefix}mask({ty} %s, {ty} %w)
  ret {ty} %r
}

define internal {ty} @{prefix}zext({ty} %v, {ty} %f, {ty} %w) {
entry:
  %a = call {ty} @{prefix}mask({ty} %v, {ty} %f)
  %r = call {ty} @{prefix}mask({ty} %a, {ty} %w)
  ret {ty} %r
}

"#;

/// Emit LLVM target-intrinsic declarations (`axis.llvm-intrinsics.v1`) as
/// TableGen `Intrinsic<>` records. With `TargetPrefix = "axis"`, each
/// `def int_axis_<name>` declares the `llvm.axis.<name>` intrinsic that an
/// out-of-tree AXIS backend lowers to the custom instruction; result and
/// argument types come straight from the instruction's operand widths (the
/// invariant `tests/golden.rs` pins). An intrinsic is emitted only for
/// instructions with pure `formal_semantics` — the same set that gets an
/// `axis_eval_*` reference body in `axis_semantics.ll` — so the
/// `IntrNoMem`/`IntrWillReturn`/`IntrSpeculatable` markers are sound;
/// instructions with unmodeled effects are withheld with a comment.
pub fn emit_llvm_intrinsics(document: &Document) -> String {
    let mut out = String::new();
    out.push_str(
        "//===-- AxisIntrinsics.td - AXIS target intrinsics ---------*- tablegen -*-===//\n",
    );
    out.push_str("// Generated by AXIS. schema: axis.llvm-intrinsics.v1\n");
    out.push_str("// Declares llvm.axis.* intrinsics from instruction signatures. AXIS\n");
    out.push_str("// instructions are pure by design; effects are not modeled yet.\n\n");
    out.push_str("let TargetPrefix = \"axis\" in {\n");
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    for instruction in &document.instructions {
        emit_llvm_intrinsic_record(&mut out, instruction, &state_names);
    }
    out.push_str("}\n");
    out
}

fn emit_llvm_intrinsic_record(
    out: &mut String,
    instruction: &Instruction,
    state_names: &[String],
) {
    // The memory attributes come from the instruction's effect summary rather
    // than from a purity guess. A pure `formal_semantics` body (the same set
    // that gets an `axis_eval_*` function) is `IntrNoMem`; a behavior that only
    // touches memory gets the matching read/write marker; anything else is
    // withheld, because LLVM has no honest spelling for it.
    let summary = crate::effects::effect_summary(instruction, state_names);
    let effectful = crate::effects::behavior_is_authoritative(instruction);
    if !effectful && instruction.formal_semantics.trim().is_empty() {
        out.push_str(&format!(
            "  // {}: no formal_semantics; effects unmodeled, intrinsic withheld\n",
            instruction.mnemonic
        ));
        return;
    }
    // An intrinsic call always produces its result. A guarded register write
    // does not: on the false path the destination keeps its old value, which a
    // pure `Intrinsic<[ty], ...>` has no way to express — it would return an
    // undefined value and, worse, be marked speculatable. Guarded *memory* is
    // fine, since "may write" is exactly what the attribute claims.
    let conditional_result = effectful
        && instruction.behavior.as_ref().is_some_and(|behavior| {
            behavior.effects.iter().any(|effect| {
                effect.guard.is_some()
                    && matches!(
                        effect.loc,
                        crate::effects::Loc::Reg(_) | crate::effects::Loc::FixedReg { .. }
                    )
            })
        });
    if conditional_result {
        out.push_str(&format!(
            "  // {}: writes its result under a guard; an intrinsic has no \
             conditional-result form, intrinsic withheld\n",
            instruction.mnemonic
        ));
        return;
    }
    if effectful && !summary.is_memory_only() {
        // Naming the reason keeps the artifact self-explanatory: a reader can
        // see that the instruction was understood and deliberately withheld.
        let reason = if summary.writes_pc {
            "writes pc; control flow has no intrinsic form"
        } else if summary.may_trap {
            "may trap; exceptional control flow has no intrinsic form"
        } else if summary.barrier {
            "is an ordering barrier, not a value computation"
        } else {
            "touches architectural state LLVM cannot see"
        };
        out.push_str(&format!(
            "  // {}: {}, intrinsic withheld\n",
            instruction.mnemonic, reason
        ));
        return;
    }
    let result = instruction.operands.iter().find(|operand| operand.output);
    let result_types = match result {
        Some(operand) => match llvm_intrinsic_type(operand.width) {
            Some(ty) => vec![ty.to_string()],
            None => {
                out.push_str(&format!(
                    "  // {}: result width {} has no standard LLVM intrinsic type\n",
                    instruction.mnemonic, operand.width
                ));
                return;
            }
        },
        None => Vec::new(),
    };
    let mut param_types = Vec::new();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        match llvm_intrinsic_type(operand.width) {
            Some(ty) => param_types.push(ty.to_string()),
            None => {
                out.push_str(&format!(
                    "  // {}: operand `{}` width {} has no standard LLVM intrinsic type\n",
                    instruction.mnemonic, operand.name, operand.width
                ));
                return;
            }
        }
    }
    // `IntrReadMem` asserts the intrinsic does not write and `IntrWriteMem`
    // that it does not read, so an instruction doing both carries neither and
    // is simply not `IntrNoMem`. A memory access can fault, so it is never
    // `IntrSpeculatable`; every AXIS instruction terminates, so all are
    // `IntrWillReturn`.
    let attributes = match (summary.reads_memory, summary.writes_memory) {
        (false, false) => "IntrNoMem, IntrWillReturn, IntrSpeculatable",
        (true, false) => "IntrReadMem, IntrWillReturn",
        (false, true) => "IntrWriteMem, IntrWillReturn",
        (true, true) => "IntrWillReturn",
    };
    let suffix = llvm_intrinsic_suffix(instruction);
    out.push_str(&format!(
        "  // {} => llvm.axis.{}\n",
        instruction.mnemonic, suffix
    ));
    out.push_str(&format!(
        "  def int_axis_{} : Intrinsic<[{}], [{}],\n      [{attributes}]>;\n",
        suffix.replace('.', "_"),
        result_types.join(", "),
        param_types.join(", ")
    ));
}

/// Dotted intrinsic name suffix (e.g. `fma.i`) for the `llvm.axis.<suffix>`
/// intrinsic. Prefers the instruction's explicit `intrinsic` field (with any
/// `llvm.`/`axis.` prefix stripped) and otherwise derives it from the
/// mnemonic. Non-alphanumeric runs become `.` segment separators.
fn llvm_intrinsic_suffix(instruction: &Instruction) -> String {
    let raw = if instruction.intrinsic.is_empty() {
        instruction.mnemonic.to_ascii_lowercase()
    } else {
        let stripped = instruction
            .intrinsic
            .strip_prefix("llvm.")
            .unwrap_or(&instruction.intrinsic);
        stripped
            .strip_prefix("axis.")
            .unwrap_or(stripped)
            .to_string()
    };
    let mut suffix = String::new();
    let mut prev_dot = true; // trims leading separators
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            suffix.push(ch.to_ascii_lowercase());
            prev_dot = false;
        } else if !prev_dot {
            suffix.push('.');
            prev_dot = true;
        }
    }
    while suffix.ends_with('.') {
        suffix.pop();
    }
    if suffix.is_empty() {
        suffix.push_str("insn");
    }
    suffix
}

/// Map an operand width to the LLVM value type used in `Intrinsic<>` records.
/// Only the standard integer widths have a prebuilt `llvm_iN_ty`; anything
/// else is reported (and the record skipped) rather than silently guessed.
fn llvm_intrinsic_type(width: u32) -> Option<&'static str> {
    Some(match width {
        1 => "llvm_i1_ty",
        8 => "llvm_i8_ty",
        16 => "llvm_i16_ty",
        32 => "llvm_i32_ty",
        64 => "llvm_i64_ty",
        _ => return None,
    })
}

/// Emit SelectionDAG lowering-pattern hints (`axis.llvm-patterns.v1`) as
/// TableGen `Pat<>` records: the LLVM IR DAG derived from an instruction's
/// `formal_semantics` on the left, the `llvm.axis.<name>` intrinsic on the
/// right — e.g. `(add (mul $rs1, $rs2), $rs3) -> int_axis_pce_fma_i`. Both
/// sides come from the same typed IR, so the mapping holds by construction. A
/// pattern is emitted only when every operand shares one standard integer
/// width (so the DAG is uniformly typed), every input is referenced (so the
/// RHS variables are bound), and the semantics map cleanly onto SelectionDAG
/// nodes; anything else is withheld with a comment.
pub fn emit_llvm_patterns(document: &Document) -> String {
    let mut out = String::new();
    out.push_str(
        "//===-- AxisPatterns.td - AXIS SelectionDAG patterns -------*- tablegen -*-===//\n",
    );
    out.push_str("// Generated by AXIS. schema: axis.llvm-patterns.v1\n");
    out.push_str("// IR-to-instruction hints: each Pat maps the DAG derived from an\n");
    out.push_str("// instruction's formal_semantics to its llvm.axis.* intrinsic.\n\n");
    emit_immediate_predicates(&mut out, document);
    for instruction in &document.instructions {
        emit_llvm_pattern_record(&mut out, document, instruction);
    }
    out
}

/// The immediate predicates the patterns below name.
///
/// Emitted into both files, from one list, because both spell the same leaf:
/// an immediate's range is a fact about the instruction, not about which file
/// is describing it.
pub(crate) fn emit_immediate_predicates(out: &mut String, document: &Document) {
    let defs = immediate_predicate_defs(document);
    if defs.is_empty() {
        return;
    }
    out.push_str("// Encoded immediates, with the values this instruction can hold:\n");
    out.push_str("// the range its semantics states, or -- failing that -- the one its\n");
    out.push_str("// encoding implies, which is not the field width.\n");
    // A scaled predicate matches the value the semantics computes and the
    // instruction encodes the quotient, so it needs the divide that gets from
    // one to the other. Declared once per scale, before anything names it.
    let mut transforms: Vec<(String, u32)> = Vec::new();
    for predicate in &defs {
        if let (Some(transform), ImmediatePredicate::Scaled { shift, .. }) =
            (predicate.transform(), predicate)
        {
            if !transforms.iter().any(|(seen, _)| *seen == transform) {
                transforms.push((transform, *shift));
            }
        }
    }
    for (transform, shift) in &transforms {
        out.push_str(&format!(
            "def {transform} : SDNodeXForm<imm, [{{\n               return CurDAG->getTargetConstant(N->getZExtValue() >> {shift}, SDLoc(N),\n             {:19}N->getValueType(0));\n}}]>;\n",
            ""
        ));
    }
    if !transforms.is_empty() {
        out.push('\n');
    }
    for predicate in defs {
        let (name, width, test) = (predicate.name(), predicate.width(), predicate.test());
        out.push_str(&format!(
            "def {name} : Operand<i{width}>, ImmLeaf<i{width}, [{{{test}}}]>;\n"
        ));
    }
    out.push('\n');
}

fn emit_llvm_pattern_record(out: &mut String, document: &Document, instruction: &Instruction) {
    let mnemonic = &instruction.mnemonic;
    let root_width = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    // The same DAG the target's own patterns select on, so the two files
    // cannot come to disagree about what an instruction means.
    // The scales the target reads, read here too -- the two files have to
    // spell one instruction's DAG identically or the gate that compares them
    // has nothing to compare.
    let leaf_with = |scales: &[(String, u32)]| {
        let scales = scales.to_vec();
        move |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
        let scales = scales.as_slice();
        // An extended immediate is spelled by its predicate, scaled where the
        // semantics multiplies it; anything else is typed by width, which is
        // what an intrinsic hint's leaves are. The width is the half's, not the
        // pattern's -- a load's address is not always its result's width.
        if let Some(predicate) =
            immediate_predicate_scaled(document, instruction, name, ext, width, scales)
        {
            return Some(format!("{}:${name}", predicate.name()));
        }
        if let Some((signed, bits)) = ext {
            if let Some(widened) = widening_register_extension(
                instruction,
                name,
                signed,
                bits,
                width,
                |_| format!("i{bits}:${name}"),
            ) {
                return Some(widened);
            }
            return None;
        }
        if let Some(narrowed) =
            narrowing_register_leaf(instruction, name, width, |_| format!("i{name_width}:${name}",
                name_width = instruction
                    .operands
                    .iter()
                    .find(|operand| operand.name == name)
                    .map(|operand| operand.width)
                    .unwrap_or(width)))
        {
            return Some(narrowed);
        }
        Some(format!("i{width}:${name}"))
        }
    };
    // A helper that switches on an operand has one DAG per value of it, and
    // the decode constraint says which values this instruction encodes. The
    // target specialises the same way and over the same list -- if only one
    // file did, the other would have nothing to check its patterns against.
    let specialisations: Vec<Option<(String, u32)>> =
        match selector_specializations(instruction).into_iter().next() {
            Some((name, values)) => values
                .into_iter()
                .map(|value| Some((name.clone(), value)))
                .collect(),
            None => vec![None],
        };
    let suffix = llvm_intrinsic_suffix(instruction);
    let mut emitted = 0usize;
    let mut first_reason: Option<String> = None;
    // A store has no value semantics, so the loop below declines it for
    // lacking what a store never has. It still has a pattern, and the target
    // emits one -- so this file has to, or the gate that compares the two has
    // nothing to compare and the target's store patterns go unchecked.
    if crate::effects::pure_value_semantics(instruction).is_err() {
        // An atomic read-modify-write: one node for both halves.
        if crate::effects::atomic_rmw_semantics(instruction).is_ok() {
            let rmw_leaf = |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
                if let Some(predicate) = immediate_predicate_scaled(
                    document, instruction, name, ext, width, &[],
                ) {
                    return Some(format!("{}:${name}", predicate.name()));
                }
                if ext.is_some() {
                    return None;
                }
                Some(format!("i{width}:${name}"))
            };
            match llvm_atomic_rmw_pattern_dag(document, instruction, &rmw_leaf) {
                Ok(dag) => {
                    let rhs = instruction
                        .operands
                        .iter()
                        .filter(|operand| operand.input)
                        .map(|operand| format!("${}", operand.name))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("// {mnemonic} => llvm.axis.{suffix}\n"));
                    out.push_str(&format!(
                        "def : Pat<{dag},\n          (int_axis_{} {rhs})>;\n",
                        suffix.replace('.', "_")
                    ));
                    return;
                }
                Err(reason) => {
                    out.push_str(&format!("// {mnemonic}: {reason}; no pattern\n"));
                    return;
                }
            }
        }
        // A store that updates its base: the same DAG the target selects on,
        // or the gate comparing the two files has nothing to compare and the
        // target's patterns go unproved.
        if crate::effects::indexed_store_semantics(instruction).is_ok() {
            let indexed_leaf = |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
                if let Some(predicate) = immediate_predicate_scaled(
                    document, instruction, name, ext, width, &[],
                ) {
                    return Some(format!("{}:${name}", predicate.name()));
                }
                if ext.is_some() {
                    return None;
                }
                Some(format!("i{width}:${name}"))
            };
            match llvm_indexed_store_pattern_dag(document, instruction, &indexed_leaf) {
                Ok((dag, _)) => {
                    let rhs = instruction
                        .operands
                        .iter()
                        .filter(|operand| operand.input)
                        .map(|operand| format!("${}", operand.name))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("// {mnemonic} => llvm.axis.{suffix}\n"));
                    out.push_str(&format!(
                        "def : Pat<{dag},\n          (int_axis_{} {rhs})>;\n",
                        suffix.replace('.', "_")
                    ));
                    return;
                }
                Err(reason) => {
                    out.push_str(&format!("// {mnemonic}: {reason}; no pattern\n"));
                    return;
                }
            }
        }
        if store_root_width(instruction).is_some() {
            let store_scales = scaled_store_immediates(instruction);
            let store_leaf = |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
                if let Some(predicate) = immediate_predicate_scaled(
                    document,
                    instruction,
                    name,
                    ext,
                    width,
                    store_scales.as_slice(),
                ) {
                    return Some(format!("{}:${name}", predicate.name()));
                }
                if ext.is_some() {
                    return None;
                }
                Some(format!("i{width}:${name}"))
            };
            match llvm_store_pattern_dag(document, instruction, &store_leaf) {
                Ok(dag) => {
                    let rhs = instruction
                        .operands
                        .iter()
                        .filter(|operand| operand.input)
                        .map(|operand| format!("${}", operand.name))
                        .collect::<Vec<_>>()
                        .join(", ");
                    out.push_str(&format!("// {mnemonic} => llvm.axis.{suffix}\n"));
                    out.push_str(&format!(
                        "def : Pat<{dag},\n          (int_axis_{} {rhs})>;\n",
                        suffix.replace('.', "_")
                    ));
                    return;
                }
                Err(reason) => {
                    out.push_str(&format!("// {mnemonic}: {reason}; no pattern\n"));
                    return;
                }
            }
        }
    }
    for pinned in &specialisations {
        let pin = pinned.as_ref().map(|(name, value)| (name.as_str(), *value));
        // This specialisation's scale, not the instruction's: `sh = 0` and
        // `sh = 1` shift by nothing and by twelve, and one answer for both
        // gives the second form the first one's.
        let leaf = leaf_with(&scaled_immediates(instruction, pin));
        let dag = match llvm_pattern_dag(document, instruction, &leaf, pin) {
            Ok(dag) => dag,
            Err(reason) => {
                first_reason.get_or_insert(reason);
                continue;
            }
        };
        // A pinned operand is passed as the literal this pattern is for, in
        // the position it occupies -- the checker reads the argument list
        // positionally and needs the value, not a hole.
        let rhs = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|op| match pin {
                Some((name, value)) if name == op.name => value.to_string(),
                _ => format!("${}", op.name),
            })
            .collect::<Vec<_>>()
            .join(", ");
        // The root carries its type, as the target's does. Without it the file
        // never states what a pattern *produces* -- which is the same width as
        // its leaves for everything except a load whose address is wider than
        // its result, and there the checker had to guess and guessed the
        // address. AArch64's `LDRB_W` reads a byte into a `W` register through
        // an `X` address, and 16 patterns disagreed with the golden model for
        // exactly that reason.
        let root_type = super::llvm_target::value_type(root_width);
        out.push_str(&format!("// {mnemonic} => llvm.axis.{suffix}\n"));
        out.push_str(&format!(
            "def : Pat<({root_type} {dag}),\n          (int_axis_{} {rhs})>;\n",
            suffix.replace('.', "_")
        ));
        emitted += 1;
    }
    if emitted == 0 {
        let reason = first_reason.unwrap_or_else(|| "no pattern for any form".to_string());
        out.push_str(&format!("// {mnemonic}: {reason}; no pattern\n"));
    }
}

/// The TableGen name for an encoded immediate whose semantics extends it from
/// `bits`, or `None` if this operand cannot honestly carry that predicate.
///
/// The range is not invented and it is not the field width. It is the
/// extension the description already writes: `(add i32 rs1 (sext i32 12 imm))`
/// says, in the semantics, that this immediate is a signed 12-bit value. A
/// predicate built from the *field* width instead would be a guess -- a signed
/// 12-bit immediate and a 12-bit shift amount occupy the same bits and accept
/// different values -- and a predicate that accepted too much tells LLVM it
/// can select the instruction for values it cannot encode.
///
/// So the two facts are cross-checked rather than assumed to agree: the
/// semantics says how many bits are meaningful, the layout says which bits are
/// encoded, and unless the encoding carries exactly `bits` of the operand
/// starting at its bit 0 there is no predicate to write. LUI is the case that
/// makes this concrete -- its immediate is encoded from bit 12 up, so its low
/// bits are not in the instruction at all.
pub(crate) fn immediate_predicate(
    document: &Document,
    instruction: &Instruction,
    name: &str,
    signed: bool,
    bits: u32,
    root_width: u32,
) -> Option<String> {
    immediate_predicate_of(document, instruction, name, Some((signed, bits)), root_width)
        .map(|predicate| predicate.name())
}

/// Whether a sorted value set is exactly `0..n`.
fn contiguous_from_zero(values: &[u32]) -> bool {
    values
        .iter()
        .enumerate()
        .all(|(index, value)| *value as usize == index)
}

/// What an immediate operand is allowed to hold.
///
/// Three shapes, in the order they are trusted. A range the *semantics*
/// states is best: `(sext i32 12 imm)` says signed 12-bit and means it. A set
/// a *decode constraint* states is next. Failing both, the *encoding* still
/// says something exact -- and it is not the field width.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ImmediatePredicate {
    /// `(sext iW N imm)` -- the semantics says signed `N`-bit.
    Signed { bits: u32, width: u32 },
    /// `(zext iW N imm)`, or an encoding covering bits `0..N` -- unsigned `N`-bit.
    Unsigned { bits: u32, width: u32 },
    /// The encoding covers a set of bits that is not a low run, so the value
    /// must be zero everywhere else. RISC-V's `LUI` is the case: its operand
    /// is a full 32-bit value of which only bits 31:12 are in the
    /// instruction, so the immediates it can encode are exactly those whose
    /// low twelve bits are clear.
    Encodable { mask: u64, width: u32 },
    /// A decode constraint names the values outright, and they need not be a
    /// power-of-two range. AArch64's shifted-register `ADD` permits
    /// `shift < 3` -- LSL, LSR, ASR and not ROR -- inside a two-bit field, so
    /// the field says four values and the machine accepts three.
    Values { values: Vec<u32>, width: u32 },
    /// The encoded field is the value *divided* by a power of two, because the
    /// semantics multiplies it back. AArch64's unsigned-offset `LDR` encodes a
    /// twelve-bit field and addresses `rn + imm * 8`, so a pattern matches a
    /// byte offset that is a multiple of eight and fits in fifteen bits.
    Scaled {
        inner: Box<ImmediatePredicate>,
        shift: u32,
    },
}

impl ImmediatePredicate {
    pub(crate) fn name(&self) -> String {
        match self {
            Self::Signed { bits, width } => format!("simm{bits}i{width}"),
            Self::Unsigned { bits, width } => format!("uimm{bits}i{width}"),
            Self::Encodable { mask, width } => format!("maskimm{mask:x}i{width}"),
            Self::Scaled { inner, shift } => {
                let base = inner.name();
                let width = inner.width();
                format!(
                    "{}s{}i{width}",
                    base.rsplit_once(&format!("i{width}"))
                        .map(|(head, _)| head.to_string())
                        .unwrap_or(base),
                    1u32 << shift
                )
            }
            Self::Values { values, width } => {
                if contiguous_from_zero(values) {
                    format!("uimmlt{}i{width}", values.len())
                } else {
                    format!(
                        "imm{}i{width}",
                        values
                            .iter()
                            .map(|value| value.to_string())
                            .collect::<Vec<_>>()
                            .join("_")
                    )
                }
            }
        }
    }

    pub(crate) fn width(&self) -> u32 {
        match self {
            Self::Signed { width, .. } | Self::Unsigned { width, .. } => *width,
            Self::Encodable { width, .. } | Self::Values { width, .. } => *width,
            Self::Scaled { inner, .. } => inner.width(),
        }
    }

    /// The `SDNodeXForm` def that turns a matched value into the field the
    /// instruction encodes, if this predicate needs one.
    pub(crate) fn transform(&self) -> Option<String> {
        match self {
            Self::Scaled { shift, .. } => Some(format!("Div{}XForm", 1u32 << shift)),
            _ => None,
        }
    }

    /// The `ImmLeaf` body: C++ that is true exactly for the values this
    /// instruction can encode.
    pub(crate) fn test(&self) -> String {
        match self {
            Self::Signed { bits, .. } => format!("return isInt<{bits}>(Imm);"),
            Self::Unsigned { bits, .. } => format!("return isUInt<{bits}>(Imm);"),
            // Written against the unsigned value so the sign bit of a negative
            // `Imm` does not light up every bit outside the mask.
            Self::Encodable { mask, .. } => format!(
                "return ((uint64_t)Imm & ~(uint64_t){mask}ULL) == 0;"
            ),
            // Two conditions, and both matter. The value has to be a multiple
            // of the scale -- an odd byte offset is not encodable at all, and
            // dividing it would silently address somewhere else -- and the
            // quotient has to be what the field holds.
            Self::Scaled { inner, shift } => {
                let scale = 1u64 << shift;
                let inner_test = inner
                    .test()
                    .replace("return ", "")
                    .replace("Imm", &format!("(Imm >> {shift})"));
                format!(
                    "return (Imm & {}) == 0 && {inner_test}",
                    scale - 1
                )
            }
            Self::Values { values, .. } => {
                if contiguous_from_zero(values) {
                    format!("return Imm >= 0 && Imm < {};", values.len())
                } else {
                    format!(
                        "return {};",
                        values
                            .iter()
                            .map(|value| format!("Imm == {value}"))
                            .collect::<Vec<_>>()
                            .join(" || ")
                    )
                }
            }
        }
    }

    /// The bits any accepted value may set -- the union of the set, which is
    /// what a checker can compare against the operand's encoded spans.
    pub(crate) fn accepted_bits(&self) -> u64 {
        match self {
            Self::Signed { bits, .. } | Self::Unsigned { bits, .. } => {
                if *bits >= 64 {
                    u64::MAX
                } else {
                    (1u64 << bits) - 1
                }
            }
            Self::Encodable { mask, .. } => *mask,
            Self::Values { values, .. } => {
                values.iter().fold(0u64, |seen, value| seen | *value as u64)
            }
            // The *encoded* bits are the inner predicate's: this one describes
            // the value before the transform divides it back down to the
            // field, and it is the field a checker compares against.
            Self::Scaled { inner, .. } => inner.accepted_bits(),
        }
    }
}

/// The predicate for one immediate operand, or `None` if this operand cannot
/// honestly carry one.
///
/// `ext` is the extension the semantics wraps the operand in, when it does.
/// With it, the range is what the description states. Without it, the range
/// comes from the layout -- which is not a guess: the encoder writes the
/// operand's bits `[op_lo, op_lo + width)` into the instruction and the
/// decoder reads them back, so a value with a bit set outside those spans is
/// one this instruction cannot represent. That set is exactly what a
/// selection predicate is for, and `roundtrip_check.py` already proves the
/// layout it comes from.
pub(crate) fn immediate_predicate_of(
    document: &Document,
    instruction: &Instruction,
    name: &str,
    ext: Option<(bool, u32)>,
    root_width: u32,
) -> Option<ImmediatePredicate> {
    let operand = instruction.operands.iter().find(|op| op.name == name)?;
    // A register's extension is a real DAG node, not a range.
    if register_class(&operand.kind).is_some() {
        return None;
    }
    if llvm_intrinsic_type(root_width).is_none() {
        return None;
    }
    let layout = layout_for(document, instruction);
    let bindings = layout.operand_bindings(name);
    if bindings.is_empty() {
        return None;
    }
    // The operand bits this instruction actually carries.
    let mut mask: u64 = 0;
    for field in &bindings {
        if field.op_lo + field.width > 64 {
            return None;
        }
        let span = if field.width >= 64 {
            u64::MAX
        } else {
            ((1u64 << field.width) - 1) << field.op_lo
        };
        mask |= span;
    }
    if mask == 0 {
        return None;
    }

    if let Some((signed, bits)) = ext {
        // The semantics says how many bits are meaningful; the layout says
        // which are encoded. Unless the encoding carries exactly those bits
        // from the operand's bit 0, there is no predicate to write.
        if bits == 0 || bits >= root_width || bits >= 64 {
            return None;
        }
        if mask != (1u64 << bits) - 1 {
            return None;
        }
        return Some(if signed {
            ImmediatePredicate::Signed {
                bits,
                width: root_width,
            }
        } else {
            ImmediatePredicate::Unsigned {
                bits,
                width: root_width,
            }
        });
    }

    // No stated range. The encoding gives an exact set -- a low run of bits is
    // an unsigned immediate of that many bits, anything else is a mask test --
    // and a decode constraint may narrow it further.
    //
    // It usually does, and the difference matters. AArch64's shifted-register
    // `ADD` holds its shift kind in a two-bit field, so the encoding says four
    // values; the constraint says `shift < 3`, because that instruction
    // encodes LSL, LSR and ASR and not ROR. A predicate taken from the field
    // alone accepts a fourth value the decoder rejects, which is the target
    // claiming an encoding that does not exist.
    if let Some(constraint) = instruction.decode_constraint.as_ref() {
        if let Some(values) = constraint.legal_values(name) {
            let permitted: Vec<u32> = values
                .into_iter()
                .filter(|value| (*value as u64) & !mask == 0)
                .collect();
            // Only when it says *less* than the field does; an exhaustive set
            // is the field's own range said twice.
            let field_values = if mask.count_ones() >= 63 {
                u64::MAX
            } else {
                mask.count_ones() as u64
            };
            if !permitted.is_empty() && (permitted.len() as u64) < (1u64 << field_values.min(32)) {
                return Some(ImmediatePredicate::Values {
                    values: permitted,
                    width: root_width,
                });
            }
        }
    }
    Some(if mask.count_ones() as u64 == 64 || (mask + 1).is_power_of_two() {
        ImmediatePredicate::Unsigned {
            bits: 64 - mask.leading_zeros(),
            width: root_width,
        }
    } else {
        ImmediatePredicate::Encodable {
            mask,
            width: root_width,
        }
    })
}

/// The `Operand`/`ImmLeaf` defs for every immediate predicate a document's
/// patterns name, in a stable order.
///
/// One def serves both roles on purpose: the Pat's LHS matches it as an
/// `ImmLeaf` predicate and the instruction's `InOperandList` types it as an
/// `Operand`, so the two sides of the pattern cannot drift apart. LLVM's own
/// RISC-V target spells `simm12` the same way.
/// The width an instruction's immediates are typed at.
///
/// Its result's, when it has one. A store has none, and the machine's word is
/// what its operands are typed at -- defaulting to 32 there gave RV64I's `SD`
/// an `Operand<i32>` slot that its own pattern contradicted. One definition,
/// because the operand list and the predicate *definitions* have to agree on
/// it or the list names a predicate that was never emitted.
/// `(zext $RN)` or `(sext $RN)` when the semantics extends a register *from its
/// own width* into a wider pattern.
///
/// This is the one extension that is a real width change. An extension inside
/// one width is a mask or a `sext_inreg` -- which is what `a64_extend_reg`
/// reduces to, over a 64-bit register whose low 8 bits are taken -- and the
/// difference is whether the register named is narrower than the pattern.
/// `UMADDL` multiplies two `W` registers into an `X`; `UXTB` takes a byte out
/// of an `X` and stays in it.
pub(crate) fn widening_register_extension(
    instruction: &Instruction,
    name: &str,
    signed: bool,
    bits: u32,
    root_width: u32,
    spell: impl Fn(&'static RegisterClass) -> String,
) -> Option<String> {
    let operand = instruction
        .operands
        .iter()
        .find(|operand| operand.name == name)?;
    let class = register_class(&operand.kind)?;
    (operand.width == bits && bits < root_width).then(|| {
        format!(
            "({} {})",
            if signed { "sext" } else { "zext" },
            spell(class)
        )
    })
}

/// `(trunc $RM)` when a register named in the pattern is *wider* than it.
///
/// The mirror of the widening rule and the same fact from the other side.
/// AArch64's `ADD_W_EXT` adds an extended `X` register to a `W` one and writes
/// a `W`: the extension happens inside 32 bits, so the 64-bit source has to
/// come down first. LLVM spells that `trunc`, and the register keeps its own
/// class -- it is the *value* that narrows, not the register file.
pub(crate) fn narrowing_register_leaf(
    instruction: &Instruction,
    name: &str,
    root_width: u32,
    spell: impl Fn(&'static RegisterClass) -> String,
) -> Option<String> {
    let operand = instruction
        .operands
        .iter()
        .find(|operand| operand.name == name)?;
    let class = register_class(&operand.kind)?;
    (operand.width > root_width).then(|| format!("(trunc {})", spell(class)))
}

/// The width one *operand* is typed at: the width of the half of the semantics
/// it appears in.
///
/// Three times now an operand has been typed at the wrong one and tblgen has
/// reported it as an empty type set, naming the pattern and never the operand
/// list that caused it -- RV64I's `SD`, a store's address offset, a load's.
/// They are one rule: an address is typed by the address, everything else by
/// the result. An instruction's operand list and its pattern have to agree,
/// and they agree by asking here.
pub(crate) fn operand_root_width(
    document: &Document,
    instruction: &Instruction,
    name: &str,
) -> u32 {
    let mentions = |expr: &SemanticExpr| {
        let mut stack = vec![expr];
        while let Some(node) = stack.pop() {
            match node {
                SemanticExpr::Atom(atom) => {
                    if atom == name {
                        return true;
                    }
                }
                SemanticExpr::List(items) => stack.extend(items.iter()),
            }
        }
        false
    };
    // A store: the address half, or the value half.
    if let Ok((value, addr, _)) = crate::effects::pure_store_semantics(instruction) {
        if let Some((value_width, addr_width)) =
            crate::effects::store_operand_widths(instruction)
        {
            if mentions(&addr) && !mentions(&value) {
                return addr_width;
            }
            return value_width;
        }
    }
    // A load: everything under the memory node is the address.
    if let Ok(expr) = crate::effects::pure_value_semantics(instruction) {
        if let Some((_, _, addr)) = peel_load(&expr) {
            if mentions(addr) {
                if let Some(width) = address_register_width(instruction, addr) {
                    return width;
                }
            }
        }
    }
    pattern_root_width(document, instruction)
}

pub(crate) fn pattern_root_width(document: &Document, instruction: &Instruction) -> u32 {
    instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .or_else(|| {
            document
                .isas
                .iter()
                .find(|isa| isa.name == instruction.isa)
                .map(|isa| isa.word_bits)
        })
        .unwrap_or(32)
}

pub(crate) fn immediate_predicate_defs(document: &Document) -> Vec<ImmediatePredicate> {
    let mut found: Vec<ImmediatePredicate> = Vec::new();
    for instruction in &document.instructions {
        let root_width = pattern_root_width(document, instruction);
        for operand in &instruction.operands {
            // The extensions the semantics states, then -- if it states none --
            // the range the encoding implies.
            let mut exts: Vec<Option<(bool, u32)>> = semantic_extensions_of(instruction, &operand.name)
                .into_iter()
                .map(Some)
                .collect();
            exts.push(None);
            // Both the plain predicate and -- where a pattern scales this
            // operand -- the scaled one, because a pattern names the latter
            // and every name a pattern uses has to be defined.
            // Every specialisation's scale, because each is a name a pattern
            // uses and every name a pattern uses has to be defined. AArch64's
            // `ADD` immediate scales by 1 and by 4096 depending on its shift
            // selector, and asking without pinning one gets only the first.
            let mut scaled: Vec<Vec<(String, u32)>> = vec![Vec::new()];
            let pins: Vec<Option<(String, u32)>> =
                match selector_specializations(instruction).into_iter().next() {
                    Some((name, values)) => values
                        .into_iter()
                        .map(|value| Some((name.clone(), value)))
                        .collect(),
                    None => vec![None],
                };
            for pin in &pins {
                let found = scaled_immediates(
                    instruction,
                    pin.as_ref().map(|(name, value)| (name.as_str(), *value)),
                );
                if !found.is_empty() && !scaled.contains(&found) {
                    scaled.push(found);
                }
            }
            let store_found = scaled_store_immediates(instruction);
            if !store_found.is_empty() && !scaled.contains(&store_found) {
                scaled.push(store_found);
            }
            let scales: Vec<&[(String, u32)]> =
                scaled.iter().map(|found| found.as_slice()).collect();
            // A store's offset is typed at its *address's* width, which need
            // not be the width above -- AArch64 stores a `W` register through
            // an `X` address. Both widths, or the operand list names a
            // predicate that was never defined.
            let mut widths = vec![root_width];
            for width in [
                operand_root_width(document, instruction, &operand.name),
                pattern_root_width(document, instruction),
            ] {
                if !widths.contains(&width) {
                    widths.push(width);
                }
            }
            for ext in exts {
                for scale in &scales {
                    for width in &widths {
                        let Some(predicate) = immediate_predicate_scaled(
                            document,
                            instruction,
                            &operand.name,
                            ext,
                            *width,
                            scale,
                        ) else {
                            continue;
                        };
                        if !found.contains(&predicate) {
                            found.push(predicate);
                        }
                    }
                }
            }
        }
    }
    found.sort_by_key(|predicate| predicate.name());
    found
}

/// Every `(signed, bits)` extension the instruction's semantics applies
/// directly to `name`.
pub(crate) fn semantic_extensions_of(instruction: &Instruction, name: &str) -> Vec<(bool, u32)> {
    // The behavior counts, not only `formal_semantics`. RISC-V's `LW` says
    // `(set rd (load i32 signed (add rs1 (sext i32 12 imm))))` and has no
    // formal form, so reading only the latter left its offset with no stated
    // range -- and the encoding, asked next, says a twelve-bit *field*. The
    // target declared `uimm12i32` for an immediate the description sign
    // extends, which is half the legal encodings of every load and store in
    // the ISA refused.
    // A store has no value semantics at all, and its extends are in the two
    // expressions it does have. Without this its offset had the same complaint
    // the loads had -- `SW` sign extends `imm` and the operand list said
    // `uimm12i32`, and the pattern's two halves disagreed about which.
    let expressions = match crate::effects::pure_value_semantics(instruction) {
        Ok(expr) => vec![expr],
        Err(_) => match crate::effects::pure_store_semantics(instruction) {
            Ok((value, addr, _)) => vec![value, addr],
            // And an indexed store's offset, which lives in the base update
            // and not in either of the two above. Its `simm9` was reading
            // `uimm9` for exactly the reason `SW`'s did, one shape further on.
            Err(_) => match crate::effects::indexed_store_semantics(instruction) {
                Ok(indexed) => vec![indexed.value, indexed.offset],
                Err(_) => return Vec::new(),
            },
        },
    };
    let root_width = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    let mut out = Vec::new();
    for expression in &expressions {
        // A load's extends are in its address.
        let inner = peel_load(expression)
            .map(|(_, _, addr)| addr)
            .unwrap_or(expression);
        let Ok(sem) = lower(inner, root_width) else {
            continue;
        };
        collect_extensions(&sem, name, &mut out);
    }
    out
}

fn collect_extensions(sem: &Sem, name: &str, out: &mut Vec<(bool, u32)>) {
    match sem {
        Sem::Ext {
            op,
            arg,
            from_bits,
            ..
        } => {
            // The float conversions count too. They are `Sem::Ext` for the
            // same reason `sext` is -- an operator carrying a source width
            // beside its result width -- and a register read at that source
            // width is no more a mismatch here than a widened one is.
            // `SCVTF_D_W` reads a `W` and writes a double; without this it was
            // declined for "mixed or non-standard operand widths", which sends
            // a reader to the register classes for a gap that is really in the
            // operator table -- `SCVTF_D_X`, the same conversion at one width,
            // says so plainly.
            if let (Sem::Sym(symbol), Op::Sext | Op::Zext | Op::FcvtS2F | Op::FcvtU2F) =
                (arg.as_ref(), op)
            {
                if symbol == name {
                    let entry = (matches!(op, Op::Sext | Op::FcvtS2F), *from_bits);
                    if !out.contains(&entry) {
                        out.push(entry);
                    }
                }
            }
            collect_extensions(arg, name, out);
        }
        Sem::App { args, .. } => args
            .iter()
            .for_each(|arg| collect_extensions(arg, name, out)),
        _ => {}
    }
}

/// How a pattern leaf is spelled, given its name and -- when the semantics
/// wraps it in an extension -- the `(signed, bits)` of that extension.
///
/// Returning `None` for an extension means "this symbol is not an encoded
/// immediate", and the extension is built as a real DAG node instead.
/// Returning `None` for a plain symbol declines the pattern outright.
/// The third argument is the width the *half of the pattern this leaf appears
/// in* is typed at, which is not always the pattern's. A load reads a byte
/// into a `W` register through an `X` address, and an immediate in that
/// address is typed by the address.
pub(crate) type PatternLeaf<'a> =
    dyn Fn(&str, Option<(bool, u32)>, u32) -> Option<String> + 'a;

/// Rewrite the helper operators a pattern can express, and leave the rest.
///
/// `a64_shift_reg(w, value, shift, amount)` selects between LSL/LSR/ASR/ROR on
/// its `shift` argument. When that argument is an *operand* the instruction
/// encodes a dynamic shift kind, and there is no single SelectionDAG node for
/// "one of four shifts" -- those stay unreduced and are declined. When it is a
/// literal, as it is for LSLV/LSRV/ASRV/RORV, the helper collapses to exactly
/// one node.
///
/// The reduction is transcribed from the generated golden model's own
/// definition of the helper, including its mask of the amount to `width - 1`.
/// It is not taken on trust: `llvm_patterns_check.py` evaluates the resulting
/// DAG against that model, which implements the helper independently in
/// Python, so a reduction that is wrong in any bit fails the gate.
fn reduce_pattern_helpers(expr: &SemanticExpr) -> SemanticExpr {
    let SemanticExpr::List(items) = expr else {
        return expr.clone();
    };
    let reduced: Vec<SemanticExpr> = items.iter().map(reduce_pattern_helpers).collect();
    let Some(SemanticExpr::Atom(op)) = reduced.first() else {
        return SemanticExpr::List(reduced);
    };
    if op == "a64_extend_reg" {
        return reduce_extend_reg(&reduced);
    }
    if op != "a64_shift_reg" {
        return SemanticExpr::List(reduced);
    }
    // `(a64_shift_reg iW value shift amount)`.
    let [_, SemanticExpr::Atom(width_atom), value, SemanticExpr::Atom(shift), amount] =
        &reduced[..]
    else {
        return SemanticExpr::List(reduced);
    };
    let Ok(selector) = shift.parse::<u32>() else {
        return SemanticExpr::List(reduced);
    };
    let Some(width) = width_atom.strip_prefix('i').and_then(|w| w.parse::<u32>().ok()) else {
        return SemanticExpr::List(reduced);
    };
    let node = match selector & 3 {
        0 => "shl",
        1 => "lshr",
        2 => "ashr",
        _ => "ror",
    };
    // The amount is masked to `width - 1` by the helper itself, and LLVM's
    // shift nodes are poison past the width, so the mask is part of the
    // meaning rather than a tidy-up.
    let masked = SemanticExpr::List(vec![
        SemanticExpr::Atom("and".to_string()),
        SemanticExpr::Atom(width_atom.clone()),
        amount.clone(),
        SemanticExpr::Atom(format!("{}", width - 1)),
    ]);
    SemanticExpr::List(vec![
        SemanticExpr::Atom(node.to_string()),
        SemanticExpr::Atom(width_atom.clone()),
        value.clone(),
        masked,
    ])
}

/// The expression a pattern is built from: what the instruction computes,
/// with the helper operators a DAG can express already reduced.
///
/// The inference lives in `effects.rs` because the golden model needs the same
/// one -- an instruction that states itself through a `behavior` was invisible
/// to both, and fixing it in one place only would have produced patterns
/// nothing could check.
fn pattern_semantics_pinned(
    instruction: &Instruction,
    pinned: Option<(&str, u32)>,
) -> Result<SemanticExpr, String> {
    let expr = crate::effects::pure_value_semantics(instruction)?;
    let expr = match pinned {
        Some((name, value)) => substitute_operand(&expr, name, value),
        None => expr,
    };
    Ok(reduce_pattern_helpers(&expr))
}

/// The predicate for one immediate, scaled if the semantics multiplies it.
///
/// One place, because both pattern files need the same answer and the target
/// additionally needs the transform that inverts it. Two walks would be two
/// answers.
pub(crate) fn immediate_predicate_scaled(
    document: &Document,
    instruction: &Instruction,
    name: &str,
    ext: Option<(bool, u32)>,
    root_width: u32,
    scaled: &[(String, u32)],
) -> Option<ImmediatePredicate> {
    let inner = immediate_predicate_of(document, instruction, name, ext, root_width)?;
    match scaled.iter().find(|(scaled_name, _)| scaled_name == name) {
        Some((_, shift)) => Some(ImmediatePredicate::Scaled {
            inner: Box::new(inner),
            shift: *shift,
        }),
        None => Some(inner),
    }
}

/// Immediate operands the semantics multiplies by a power of two, and the
/// shift it multiplies by.
///
/// AArch64's unsigned-offset `LDR` addresses `rn + imm * 8` and encodes the
/// twelve-bit `imm`. Selection sees the *byte* offset, because that is what a
/// `load` node's address is, so the pattern has to match `rn + N` for an `N`
/// that is a multiple of eight -- and hand the instruction `N / 8`.
///
/// Both pattern files read this rather than each finding the shifts itself:
/// the target has to divide the value on the way to the instruction and the
/// intrinsic hints have to say the same DAG, and a second walk of the
/// semantics is a second answer waiting to disagree.
pub(crate) fn scaled_immediates(
    instruction: &Instruction,
    pinned: Option<(&str, u32)>,
) -> Vec<(String, u32)> {
    let Ok(expr) = pattern_semantics_pinned(instruction, pinned) else {
        return Vec::new();
    };
    let expr = peel_load(&expr).map(|(_, _, addr)| addr).unwrap_or(&expr);
    let root_width = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    let Ok(sem) = lower(expr, root_width) else {
        return Vec::new();
    };
    let sem = fold_constant_arithmetic(&sem);
    let is_immediate = |name: &str| {
        instruction
            .operands
            .iter()
            .any(|operand| operand.name == name && register_class(&operand.kind).is_none())
    };
    let mut found = Vec::new();
    collect_scaled(&sem, &is_immediate, &mut found);
    found
}

fn collect_scaled(sem: &Sem, is_immediate: &dyn Fn(&str) -> bool, out: &mut Vec<(String, u32)>) {
    match sem {
        Sem::App { op, args, .. } => {
            // `(shl <immediate> <literal>)` and nothing else. A shift by a
            // second *operand* is a dynamic scale, which no predicate can
            // state; a shift of a register is an ordinary DAG node.
            if let (Op::Shl, [Sem::Sym(name), Sem::Int { value, .. }]) = (op, &args[..]) {
                if is_immediate(name) && *value > 0 && *value < 32 {
                    let entry = (name.clone(), *value as u32);
                    if !out.contains(&entry) {
                        out.push(entry);
                    }
                    return;
                }
            }
            args.iter().for_each(|arg| collect_scaled(arg, is_immediate, out));
        }
        Sem::Ext { arg, .. } => collect_scaled(arg, is_immediate, out),
        _ => {}
    }
}

/// Replace each `(shl <immediate> k)` with the immediate itself, so the DAG
/// matches the product and the operand's predicate carries the scale.
fn fold_scaled_immediates(sem: &Sem, scaled: &[(String, u32)]) -> Sem {
    if let Sem::App { op, args, .. } = sem {
        if let (Op::Shl, [Sem::Sym(name), Sem::Int { .. }]) = (op, &args[..]) {
            if scaled.iter().any(|(scaled_name, _)| scaled_name == name) {
                return Sem::Sym(name.clone());
            }
        }
    }
    match sem {
        Sem::App { op, width, args } => Sem::App {
            op: *op,
            width: *width,
            args: args
                .iter()
                .map(|arg| fold_scaled_immediates(arg, scaled))
                .collect(),
        },
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => Sem::Ext {
            op: *op,
            width: *width,
            from_bits: *from_bits,
            arg: Box::new(fold_scaled_immediates(arg, scaled)),
        },
        other => other.clone(),
    }
}

/// `(a64_extend_reg iW value option amount)` with its `option` pinned.
///
/// The option chooses a source width *and* a signedness -- `8 << (option & 3)`
/// bits, sign-extended when bit 2 is set -- and then shifts left by `amount`.
/// Pinned, that is an extension of a register and a shift, both of which are
/// ordinary DAG nodes; unpinned it is neither, which is why the whole
/// extended-register family had no pattern.
///
/// Nothing here knows the mnemonics UXTB or SXTW. It reads the arithmetic the
/// helper performs, which the golden model performs too.
fn reduce_extend_reg(reduced: &[SemanticExpr]) -> SemanticExpr {
    let [_, SemanticExpr::Atom(width_atom), value, SemanticExpr::Atom(option), amount] = reduced
    else {
        return SemanticExpr::List(reduced.to_vec());
    };
    let (Ok(option), Some(width)) = (
        option.parse::<u32>(),
        width_atom.strip_prefix('i').and_then(|w| w.parse::<u32>().ok()),
    ) else {
        return SemanticExpr::List(reduced.to_vec());
    };
    let source_bits = 8u32 << (option & 3);
    // A source at least as wide as the register extends nothing: `UXTX` into
    // an X register is the register.
    let extended = if source_bits >= width {
        value.clone()
    } else {
        SemanticExpr::List(vec![
            SemanticExpr::Atom(
                if option & 4 != 0 { "sext" } else { "zext" }.to_string(),
            ),
            SemanticExpr::Atom(width_atom.clone()),
            SemanticExpr::Atom(source_bits.to_string()),
            value.clone(),
        ])
    };
    SemanticExpr::List(vec![
        SemanticExpr::Atom("shl".to_string()),
        SemanticExpr::Atom(width_atom.clone()),
        extended,
        amount.clone(),
    ])
}

/// Operands a helper switches on, and the values a decode constraint permits
/// them to take.
///
/// `a64_shift_reg(w, value, shift, amount)` chooses between LSL, LSR, ASR and
/// ROR on its third argument. There is no SelectionDAG node for "one of four
/// shifts", so while that argument is an operand the instruction has no
/// pattern at all -- which is what declined every shifted-register `ADD`,
/// `SUB`, `AND`, `ORR` and `EOR` in the corpus.
///
/// It does have one *per shift kind*, and the description says which kinds it
/// encodes: `a64_shifted_reg` permits `shift < 3`, so the shifted-register
/// `ADD` gets three patterns and no ROR variant, because that instruction
/// genuinely cannot encode one. Nothing here knows that; it reads the
/// constraint.
pub(crate) fn selector_specializations(
    instruction: &Instruction,
) -> Vec<(String, Vec<u32>)> {
    let Ok(expr) = crate::effects::pure_value_semantics(instruction) else {
        return Vec::new();
    };
    let mut names: Vec<(String, bool)> = Vec::new();
    collect_selector_operands(&expr, &mut names);
    names
        .into_iter()
        .filter(|(name, _)| {
            instruction
                .operands
                .iter()
                .any(|operand| operand.name == *name && register_class(&operand.kind).is_none())
        })
        .filter_map(|(name, is_helper_choice)| {
            // What the decoder accepts, when a constraint says so.
            let stated = instruction
                .decode_constraint
                .as_ref()
                .and_then(|constraint| constraint.legal_values(&name));
            // Failing that, a *narrow field* enumerates itself. AArch64's
            // `ADD` immediate holds its shift selector in one bit, so the
            // encoding says two values and says it exactly; nothing else in
            // the description needed to. The bound is what keeps this from
            // turning a twelve-bit immediate into four thousand patterns --
            // an operand a pattern specialises over is a *choice*, and a
            // choice is small.
            let values = stated.or_else(|| {
                let width = instruction
                    .operands
                    .iter()
                    .find(|operand| operand.name == name)?
                    .width;
                // A helper's selector is a choice by construction -- there is
                // no node for "one of these", which is the whole reason it is
                // being specialised -- so its field enumerates however wide it
                // is. `a64_extend_reg` picks among eight source-width and
                // signedness pairs and needs all eight.
                //
                // An operand that merely appears in a shift *amount* is only a
                // choice if it is small: the two-bit bound is what keeps a
                // twelve-bit immediate from becoming four thousand patterns.
                (is_helper_choice || width <= SELECTOR_FIELD_BITS)
                    .then(|| (0..1u32 << width).collect())
            })?;
            (values.len() > 1).then_some((name, values))
        })
        .collect()
}

/// How wide a field may be for its own range to enumerate a selector.
const SELECTOR_FIELD_BITS: u32 = 2;

/// The argument index each helper switches on, counting the operator itself as
/// zero. A helper not named here has no selector.
fn helper_selector_index(op: &str) -> Option<usize> {
    match op {
        // `(a64_shift_reg iW value shift amount)`
        "a64_shift_reg" => Some(3),
        // `(a64_extend_reg iW value option amount)`
        "a64_extend_reg" => Some(3),
        _ => None,
    }
}

fn collect_selector_operands(expr: &SemanticExpr, out: &mut Vec<(String, bool)>) {
    let SemanticExpr::List(items) = expr else {
        return;
    };
    let mut push = |name: &str, is_helper_choice: bool| {
        if !out.iter().any(|(seen, _)| seen == name) {
            out.push((name.to_string(), is_helper_choice));
        }
    };
    if let Some(SemanticExpr::Atom(op)) = items.first() {
        if let Some(index) = helper_selector_index(op) {
            if let Some(SemanticExpr::Atom(name)) = items.get(index) {
                if name.parse::<u32>().is_err() {
                    push(name, true);
                }
            }
        }
        // An operand in a shift *amount* is a selector for the same reason a
        // shift kind is: there is no node for "shifted by one of these". A
        // helper switching on it is one way to say that; AArch64's `ADD`
        // immediate says it in the open, as `(shl imm (mul sh 12))`, where
        // `sh` chooses between shifting by nothing and by twelve. Pin it and
        // the scale is a constant, which is a form that does have a pattern.
        if op == "shl" {
            for name in shift_amount_operands(items.last()) {
                push(&name, false);
            }
        }
    }
    drop(push);
    for item in items {
        collect_selector_operands(item, out);
    }
}

/// The operand names a shift amount is built from, when it is not a literal.
///
/// Only an arithmetic expression over operands and constants counts. A shift
/// by a *register* is an ordinary dynamic shift with a DAG node of its own,
/// and pinning it would be inventing a constant the machine does not have.
fn shift_amount_operands(amount: Option<&SemanticExpr>) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack: Vec<&SemanticExpr> = amount.into_iter().collect();
    while let Some(node) = stack.pop() {
        match node {
            SemanticExpr::Atom(atom) => {
                if atom.parse::<u32>().is_err()
                    && !atom.starts_with('i')
                    && !found.contains(atom)
                {
                    found.push(atom.clone());
                }
            }
            SemanticExpr::List(items) => stack.extend(items.iter()),
        }
    }
    found
}

/// Replace every mention of `name` with the literal `value`.
pub(crate) fn substitute_operand(expr: &SemanticExpr, name: &str, value: u32) -> SemanticExpr {
    match expr {
        SemanticExpr::Atom(atom) if atom == name => SemanticExpr::Atom(value.to_string()),
        SemanticExpr::Atom(_) => expr.clone(),
        SemanticExpr::List(items) => SemanticExpr::List(
            items
                .iter()
                .map(|item| substitute_operand(item, name, value))
                .collect(),
        ),
    }
}

/// Drop a mask that the operand's own predicate already enforces.
///
/// A shift amount is masked to the register width by the machine, and the
/// description says so: RISC-V's `SLLI` is `(shl rs1 (and rs2 31))`. When the
/// amount is a *register* that mask is real and LLVM writes the same DAG. When
/// it is an immediate it is not: `uimm5` already bounds the operand below 32,
/// and LLVM constant-folds `(and 5, 31)` to `5` long before selection -- so a
/// pattern demanding the `and` node matches nothing at all.
///
/// This was live: `SLLI`, `SRLI` and `SRAI` each carried a pattern that could
/// never fire. Dropping the mask is sound only because the predicate enforces
/// it, so the two are checked together -- the mask goes only when the
/// predicate's accepted bits fit inside it.
fn fold_redundant_masks(
    document: &Document,
    instruction: &Instruction,
    sem: &Sem,
    root_width: u32,
) -> Sem {
    match sem {
        Sem::App { op, width, args } => {
            let folded: Vec<Sem> = args
                .iter()
                .map(|arg| fold_redundant_masks(document, instruction, arg, root_width))
                .collect();
            if matches!(op, Op::And) {
                if let [Sem::Sym(name), Sem::Int { value, .. }] = &folded[..] {
                    let bounded = immediate_predicate_of(document, instruction, name, None, root_width)
                        .is_some_and(|predicate| predicate.accepted_bits() & !(*value as u64) == 0);
                    if bounded {
                        return Sem::Sym(name.clone());
                    }
                }
            }
            Sem::App {
                op: *op,
                width: *width,
                args: folded,
            }
        }
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => Sem::Ext {
            op: *op,
            width: *width,
            from_bits: *from_bits,
            arg: Box::new(fold_redundant_masks(document, instruction, arg, root_width)),
        },
        other => other.clone(),
    }
}

/// The selection DAG for an instruction's semantics, with leaves spelled by
/// the caller and at most one operand pinned to a literal -- or the reason
/// there is none. Pinning is how a selector's specialisations are built;
/// `None` is the whole instruction.
///
/// Both pattern files go through here: the intrinsic hints type a leaf by
/// width (`i64:$rs1`), the target's own patterns type it by register class
/// (`GPRRegs:$rs1`). Sharing the decision is the point -- a target that
/// emitted a pattern the intrinsic file declined would be selecting on a DAG
/// that `llvm_patterns_check.py` has never compared against the golden model.
pub(crate) fn llvm_pattern_dag(
    document: &Document,
    instruction: &Instruction,
    leaf: &PatternLeaf,
    pinned: Option<(&str, u32)>,
) -> Result<String, String> {
    let expr = pattern_semantics_pinned(instruction, pinned)?;
    let root_width = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    // Every *register* operand has to be the root's width, because a DAG is
    // typed at one width and a register leaf carries that type. An immediate
    // does not: its declared width is the size of the field that holds it --
    // AArch64 spells a 12-bit immediate `i12` beside its `i64` registers --
    // and what it may hold is said by its predicate, not by that width.
    // Requiring it to match declined 178 instructions for having an immediate
    // at all.
    if llvm_intrinsic_type(root_width).is_none() {
        return Err("non-standard result width".to_string());
    }
    // A load is peeled before lowering: `Sem` holds the address, and the
    // memory node wraps the DAG that address builds.
    let load = peel_load(&expr);
    let (load_node, expr) = match load {
        Some((signed, bits, addr)) => {
            if let Some(objection) = load_pattern_objection(instruction) {
                return Err(objection);
            }
            (
                Some(
                    load_sdnode(signed, bits, root_width)
                        .ok_or_else(|| format!("no SelectionDAG node for a {bits}-bit load"))?,
                ),
                addr.clone(),
            )
        }
        None => (None, expr),
    };
    // The width the expression below is typed at. For a load it is the
    // *address's*, not the result's: AArch64 reads a byte into a `W` register
    // through an `X` address, and requiring one width for both declined that
    // whole family -- 52 instructions on the seed -- for a mismatch that is
    // the architecture rather than a limit of this builder.
    //
    // Everything else has one width, and every register operand must be it,
    // because a DAG is typed at one width and a register leaf carries that
    // type. An immediate does not: its declared width is the size of the field
    // that holds it -- AArch64 spells a 12-bit immediate `i12` beside its
    // `i64` registers -- and what it may hold is said by its predicate.
    let expr_width = match &load_node {
        Some(_) => address_register_width(instruction, &expr)
            .ok_or_else(|| "the address is not formed from a register operand".to_string())?,
        None => root_width,
    };
    if llvm_intrinsic_type(expr_width).is_none() {
        return Err("non-standard address width".to_string());
    }
    // Each half's registers must agree with that half. A load's result is the
    // output operand and its address is everything else; a value's operands
    // are all one width.
    if let Some(operand) = instruction.operands.iter().find(|op| {
        if register_class(&op.kind).is_none() {
            return false;
        }
        let want = if op.output && load_node.is_some() {
            root_width
        } else {
            expr_width
        };
        if op.width == want {
            return false;
        }
        // A register the semantics *extends from its own width* is allowed to
        // be narrower: that is a widening operation, not a mismatch, and the
        // builder above makes it a real `zext`/`sext` node. `UMADDL` reads two
        // `W` registers and writes an `X`, and the description says so.
        if semantic_extensions_of(instruction, &op.name)
            .into_iter()
            .any(|(_, bits)| bits == op.width && op.width < want)
        {
            return false;
        }
        // And a register *wider* than the pattern is a truncation, which is
        // also a node. `ADD_W_EXT` adds an extended `X` to a `W`.
        op.width <= want
    }) {
        let _ = operand;
        return Err("mixed or non-standard operand widths".to_string());
    }
    let sem = lower(&expr, expr_width).map_err(|error| format!("semantics did not lower: {}", error.message))?;
    let sem = fold_constant_arithmetic(&sem);
    let sem = fold_redundant_masks(document, instruction, &sem, expr_width);
    // A scaled immediate is folded into its operand's predicate the same way a
    // redundant mask is -- except that this one is not redundant, so the
    // predicate carries the scale and the caller's RHS divides it back.
    let sem = fold_scaled_immediates(&sem, &scaled_immediates(instruction, pinned));
    let root_width = expr_width;
    let mut used = std::collections::HashSet::new();
    collect_pattern_symbols(&sem, &mut used);
    if let Some(op) = instruction
        .operands
        .iter()
        .filter(|op| op.input)
        // A pinned selector is deliberately absent from the DAG: the pattern
        // is the one for *that* value of it, and the RHS supplies the literal.
        .filter(|op| pinned.map(|(name, _)| name != op.name).unwrap_or(true))
        .find(|op| !used.contains(op.name.as_str()))
    {
        return Err(format!("input `{}` unused in semantics", op.name));
    }
    // Every leaf must be an operand of this instruction. A behavior names
    // architectural state freely -- ADC reads `nzcv`, ADR reads `pc` -- and
    // such a symbol has no operand to bind, so a pattern would hand LLVM a
    // node it cannot match. tblgen does catch it ("Node 'X' in output pattern
    // but not input pattern"), which is a crash rather than a decline; this
    // is rarely reached from `formal_semantics` and routinely from a
    // behavior, so it is named here instead.
    if let Some(symbol) = used
        .iter()
        .find(|symbol| !instruction.operands.iter().any(|op| op.name == **symbol))
    {
        return Err(format!(
            "semantics names `{symbol}`, which is not an operand"
        ));
    }
    let is_immediate = |name: &str| {
        instruction
            .operands
            .iter()
            .any(|operand| operand.name == name && register_class(&operand.kind).is_none())
    };
    if let Some(node) = constant_folded_node(&sem, &is_immediate) {
        return Err(format!("`{node}` is constant-folded before selection"));
    }
    let dag = sdnode_pattern_with(&sem, root_width, leaf)
        .ok_or_else(|| "no SelectionDAG pattern for these operators".to_string())?;
    if let Some(node) = load_node {
        // An address that is a bare register is a legitimate pattern -- the
        // bare-value objection below is about a *value*, and this one is the
        // load.
        return Ok(format!("({node} {dag})"));
    }
    if !dag.starts_with('(') {
        return Err("semantics is a bare value".to_string());
    }
    Ok(dag)
}

/// A root `(load iN signed|unsigned addr)` peeled into its access width, its
/// signedness, and the address expression underneath -- or `None` if this is
/// not a plain load.
///
/// A load is deliberately not a `Sem` operator. `Sem` is pure arithmetic, and
/// every backend that matches on it -- C, Rust, SMT, the executors -- would
/// have to learn a memory node to put one there. It does not need to: a load
/// can only be the *root* of a value, so peeling it above the lowering leaves
/// an address, which is arithmetic, to the builder that already exists.
///
/// `atomic_load` is declined, and so is a `load` carrying a memory order. A
/// `Pat` has nowhere to say an ordering, and selecting an ordered load as a
/// plain one would drop the fence the architecture promised.
fn peel_load(expr: &SemanticExpr) -> Option<(bool, u32, &SemanticExpr)> {
    let SemanticExpr::List(items) = expr else {
        return None;
    };
    // `(load <type> <signedness> [<order>] <addr>)`. The order is *accepted*
    // here and refused by `load_pattern_objection`, which reads it from the
    // effect -- refusing it by shape instead left `LDAR` unrecognised as a
    // load at all, so it declined for the width of an address the load path
    // would have handled. A decline is only useful if it names the cause.
    let [SemanticExpr::Atom(op), SemanticExpr::Atom(type_atom), SemanticExpr::Atom(sign), rest @ ..] =
        &items[..]
    else {
        return None;
    };
    // ⚠️ `atomic_load` is peeled here too, for the reason above. Marking the
    // load-reserved family atomic -- which it is -- made `LR_W` stop being a
    // load to this function, so it declined somewhere downstream and the
    // reason it used to give went missing from the output entirely. It is
    // recognised and then refused by name, which is the same rule `LDAR` is
    // already here for.
    if !matches!(op.as_str(), "load" | "atomic_load") || !matches!(rest.len(), 1 | 2) {
        return None;
    }
    let addr = rest.last()?;
    let signed = match sign.as_str() {
        "signed" => true,
        "unsigned" => false,
        _ => return None,
    };
    let bits = type_atom.strip_prefix('i')?.parse::<u32>().ok()?;
    Some((signed, bits, addr))
}

/// Why this instruction's load is not a plain `load` node, if it is not.
///
/// `pure_value_semantics` separates architectural state out as a clobber,
/// which is right for an instruction that computes a value and sets flags
/// beside it -- LLVM sees the clobber as `Defs` and the value pattern is still
/// the truth. It is not right for a load. RISC-V's `LR.W` loads *and* records
/// a reservation, and a `load` node has nowhere to carry that: selecting
/// `LR.W` for an ordinary load would claim a plain access, and LLVM would be
/// free to delete a reservation it cannot see. An ordering is the same story
/// one level down -- a `Pat` cannot say `acquire`, so `LR.W.AQ` selected as a
/// `load` drops the fence the architecture promised.
fn load_pattern_objection(instruction: &Instruction) -> Option<String> {
    let Some(behavior) = instruction.behavior.as_ref() else {
        // The load came from `formal_semantics`, which carries no effect and
        // so cannot say it is plain. Nothing in the corpora reaches this.
        return Some("a load outside a behavior cannot state its ordering".to_string());
    };
    let value = behavior
        .effects
        .iter()
        .find(|effect| matches!(effect.loc, crate::effects::Loc::Reg(_)))?;
    if value.value.load_atomic {
        return Some("an atomic load is not a plain `load` node".to_string());
    }
    if value.value.load_order != crate::effects::MemoryOrder::Relaxed {
        return Some("an ordered load is not a plain `load` node".to_string());
    }
    if behavior
        .effects
        .iter()
        .any(|effect| matches!(effect.loc, crate::effects::Loc::State { .. }))
    {
        return Some("the load writes architectural state beside its value".to_string());
    }
    None
}

/// The SelectionDAG node a load of `bits` into a `root_width` register spells.
///
/// A narrow load is `sextloadiN`/`zextloadiN` rather than a `load` followed by
/// an extend, because that is the form LLVM's DAG is in by the time selection
/// runs: the combiner folds the extension into the load. Emitting the unfolded
/// pair would be a pattern that never fires.
fn load_sdnode(signed: bool, bits: u32, root_width: u32) -> Option<String> {
    if bits == root_width {
        // A full-width load has no extension to name, and its signedness is
        // not a property of the node.
        return Some("load".to_string());
    }
    if bits > root_width || !matches!(bits, 8 | 16 | 32) {
        return None;
    }
    Some(format!(
        "{}loadi{bits}",
        if signed { "sext" } else { "zext" }
    ))
}

/// Evaluate every subtree whose arguments are all literals.
///
/// Pinning a selector turns `(mul sh 12)` into `(mul 0 12)`, which is a
/// constant the *combiner* would fold but the pattern builder would not --
/// leaving a shift amount that is an expression where a scale has to be a
/// number. Folding here is what lets the selector machinery and the scaled
/// immediates compose: one supplies the constant, the other needs it.
fn fold_constant_arithmetic(sem: &Sem) -> Sem {
    let folded = match sem {
        Sem::App { op, width, args } => Sem::App {
            op: *op,
            width: *width,
            args: args.iter().map(fold_constant_arithmetic).collect(),
        },
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => Sem::Ext {
            op: *op,
            width: *width,
            from_bits: *from_bits,
            arg: Box::new(fold_constant_arithmetic(arg)),
        },
        other => other.clone(),
    };
    let Sem::App { op, width, args } = &folded else {
        return folded;
    };
    // An identity, which pinning a selector routinely produces: `sh = 0` turns
    // `(shl imm (mul sh 12))` into `(shl imm 0)`, and that is `imm`. Left
    // standing it is a node with two constant leaves, which the
    // constant-folded check then declines -- so the unshifted half of every
    // `ADD` immediate had no pattern while the shifted half did.
    if let [value, Sem::Int { value: 0, .. }] = &args[..] {
        if matches!(op, Op::Shl | Op::Lshr | Op::Ashr | Op::Add | Op::Sub | Op::Or | Op::Xor) {
            return value.clone();
        }
    }
    if let [value, Sem::Int { value: 1, .. }] = &args[..] {
        if matches!(op, Op::Mul) {
            return value.clone();
        }
    }
    let literals: Option<Vec<u128>> = args
        .iter()
        .map(|arg| match arg {
            Sem::Int { value, .. } => Some(*value),
            _ => None,
        })
        .collect();
    let Some(values) = literals else {
        return folded;
    };
    // Only the operators whose constant value is unambiguous at this width.
    // A division has a zero case, a shift past the width is poison, and
    // neither belongs in a silent fold.
    let value = match (op, &values[..]) {
        (Op::Add, [a, b]) => a.wrapping_add(*b),
        (Op::Sub, [a, b]) => a.wrapping_sub(*b),
        (Op::Mul, [a, b]) => a.wrapping_mul(*b),
        (Op::And, [a, b]) => a & b,
        (Op::Or, [a, b]) => a | b,
        (Op::Xor, [a, b]) => a ^ b,
        (Op::Shl, [a, b]) if *b < u128::from(*width) => a << b,
        _ => return folded,
    };
    let mask = if *width >= 128 {
        u128::MAX
    } else {
        (1u128 << width) - 1
    };
    Sem::Int {
        value: value & mask,
        width: *width,
    }
}

/// Whether every leaf under this node is a constant -- a literal, or an
/// immediate operand, which is a `ConstantSDNode` by the time selection runs.
fn is_constant_tree(sem: &Sem, is_immediate: &dyn Fn(&str) -> bool) -> bool {
    match sem {
        Sem::Int { .. } => true,
        Sem::Call { .. } => false,
        Sem::Sym(name) => is_immediate(name),
        Sem::App { args, .. } => args.iter().all(|arg| is_constant_tree(arg, is_immediate)),
        Sem::Ext { arg, .. } => is_constant_tree(arg, is_immediate),
    }
}

/// A node whose operands are all constants, if there is one.
///
/// Such a node is folded away long before instruction selection -- AArch64's
/// unsigned-offset `LDR` scales its immediate, which reduces to `(shl
/// uimm12i64:$IMM, (i64 3))`, and no selected DAG has ever contained a shift
/// of one constant by another. A pattern built on it is not wrong so much as
/// dead: it matches nothing, forever, and reads as coverage.
///
/// The instruction is not unreachable, only unreachable *this way*: a scaled
/// offset needs the inverse transform on the immediate, which is an
/// `SDNodeXForm` and a description of the scale, and neither exists yet.
fn constant_folded_node(sem: &Sem, is_immediate: &dyn Fn(&str) -> bool) -> Option<String> {
    match sem {
        // A leaf is not a folded node; a whole-constant pattern is caught by
        // the unused-input and bare-value checks instead.
        Sem::Sym(_) | Sem::Int { .. } | Sem::Call { .. } => None,
        Sem::App { op, args, .. } => {
            if is_constant_tree(sem, is_immediate) {
                return Some(format!("{op:?}").to_lowercase());
            }
            args.iter()
                .find_map(|arg| constant_folded_node(arg, is_immediate))
        }
        Sem::Ext { op, arg, .. } => {
            // An extension over an encoded immediate is not a node. The DAG
            // builder absorbs it into the operand's predicate -- `(sext 12
            // imm)` is `simm12:$imm` -- so there is nothing here for the
            // combiner to fold. Every `addi`-shaped instruction in the corpus
            // reaches this arm.
            if matches!((arg.as_ref(), op), (Sem::Sym(name), Op::Sext | Op::Zext)
                if is_immediate(name))
            {
                return None;
            }
            if is_constant_tree(sem, is_immediate) {
                return Some(format!("{op:?}").to_lowercase());
            }
            constant_folded_node(arg, is_immediate)
        }
    }
}

/// The SelectionDAG pattern for an instruction whose whole behavior is one
/// plain memory write, or the reason there is none.
///
/// A store is the load's mirror and differs in the two ways that matter: it
/// has no result, so the `Pat` has no root type and none of the single-result
/// machinery applies, and it has two children rather than one -- LLVM spells
/// it `(store value, address)`, value first.
///
/// A narrow store is `truncstoreiN`, which is the same story as `sextloadiN`
/// one direction over: by selection time the combiner has folded the truncate
/// into the store, so a truncate and a store would be a pattern that never
/// fires.
pub(crate) fn llvm_store_pattern_dag(
    document: &Document,
    instruction: &Instruction,
    leaf: &PatternLeaf,
) -> Result<String, String> {
    // A scalable instruction is one encoded word per lane, and the lanes are
    // alternatives competing for it rather than distinct machine
    // instructions -- which is why every other stage takes lane 0 as the
    // representative. Its semantics names per-lane symbols (`zs__l0`) that the
    // encoded operand list does not carry, so a pattern built from them passes
    // the instruction operands it does not have.
    if !instruction.scalable_origin.is_empty() {
        return Err("a scalable instruction's operands are per-lane".to_string());
    }
    let (value, addr, access) = crate::effects::pure_store_semantics(instruction)?;
    // A store has *two* widths and conflating them is wrong. The value is
    // typed by the register it comes out of -- `(truncstorei8 (i32 $RS2), ..)`
    // narrows a whole register -- and the address is typed by the machine's
    // pointer, which LLVM takes from the target and not from this pattern.
    let root_width = store_value_width(instruction, &value)
        .ok_or_else(|| "the stored value is not a register operand".to_string())?;
    if llvm_intrinsic_type(root_width).is_none() {
        return Err("non-standard stored width".to_string());
    }
    let word_bits = document
        .isas
        .iter()
        .find(|isa| isa.name == instruction.isa)
        .map(|isa| isa.word_bits)
        .unwrap_or(root_width);
    // An address wider than the machine's word is not an address this machine
    // forms. RISC-V's `FSD` declares a 64-bit base register in a 32-bit ISA,
    // and a pattern for it contradicts the target's own pointer type -- which
    // tblgen reports as an empty type set rather than as anything readable.
    let addr_width = address_register_width(instruction, &addr)
        .ok_or_else(|| "the address is not formed from a register operand".to_string())?;
    if addr_width != word_bits {
        return Err(format!(
            "the address is {addr_width} bits and the machine's word is {word_bits}"
        ));
    }
    let node = if access == root_width {
        "store".to_string()
    } else if access < root_width && matches!(access, 8 | 16 | 32) {
        format!("truncstorei{access}")
    } else {
        return Err(format!("no SelectionDAG node for a {access}-bit store"));
    };

    let build = |expr: &SemanticExpr, root_width: u32| -> Result<String, String> {
        let expr = reduce_pattern_helpers(expr);
        let sem = lower(&expr, root_width).map_err(|error| format!("semantics did not lower: {}", error.message))?;
        let sem = fold_redundant_masks(document, instruction, &sem, root_width);
        let sem = fold_scaled_immediates(&sem, &scaled_store_immediates(instruction));
        let is_immediate = |name: &str| {
            instruction
                .operands
                .iter()
                .any(|operand| operand.name == name && register_class(&operand.kind).is_none())
        };
        if let Some(folded) = constant_folded_node(&sem, &is_immediate) {
            return Err(format!("`{folded}` is constant-folded before selection"));
        }
        let mut used = std::collections::HashSet::new();
        collect_pattern_symbols(&sem, &mut used);
        if let Some(symbol) = used
            .iter()
            .find(|symbol| !instruction.operands.iter().any(|op| op.name == **symbol))
        {
            return Err(format!(
                "semantics names `{symbol}`, which is not an operand"
            ));
        }
        sdnode_pattern_with(&sem, root_width, leaf)
            .ok_or_else(|| "no SelectionDAG pattern for these operators".to_string())
    };
    let value_dag = build(&value, root_width)?;
    let addr_dag = build(&addr, addr_width)?;
    // Every input has to appear, or the pattern hands LLVM an operand it never
    // matched. Both halves together, because a store's operands are split
    // across them.
    let both = format!("{value_dag} {addr_dag}");
    if let Some(operand) = instruction
        .operands
        .iter()
        .filter(|op| op.input)
        .find(|op| !both.contains(&format!("${}", op.name)) && !both.contains(&format!("${}", tablegen_ident(&op.name))))
    {
        return Err(format!("input `{}` unused in semantics", operand.name));
    }
    // The stored value carries its type explicitly. A store has no result, so
    // nothing else in the pattern pins one -- and a class holding more than
    // one value type, which `rv_gpr` does because the document names both 32-
    // and 64-bit operands of it, leaves tblgen unable to infer any: "Could not
    // infer all types in pattern". The load patterns annotate their root for
    // the same reason; for a store the value is the only place to say it.
    let value_type = super::llvm_target::value_type(root_width);
    Ok(format!("({node} ({value_type} {value_dag}), {addr_dag})"))
}

/// The SelectionDAG pattern for an atomic read-modify-write.
///
/// LLVM spells the whole pair one node -- `(atomic_load_add_i64_acquire $ptr,
/// $val)` -- whose result is the *old* value, which is what the register half
/// of the description holds. The operation is read from the stored
/// expression, by the same function the IR emitter has always used for it:
/// a value that does not mention the loaded register is an exchange, and one
/// that does names its operator.
pub(crate) fn llvm_atomic_rmw_pattern_dag(
    document: &Document,
    instruction: &Instruction,
    leaf: &PatternLeaf,
) -> Result<String, String> {
    if !instruction.scalable_origin.is_empty() {
        return Err("a scalable instruction's operands are per-lane".to_string());
    }
    let rmw = crate::effects::atomic_rmw_semantics(instruction)
        .map_err(|reason| reason.unwrap_or_default())?;
    let root_width = instruction
        .operands
        .iter()
        .find(|operand| operand.name == rmw.loaded)
        .map(|operand| operand.width)
        .ok_or_else(|| "the loaded value is not an operand".to_string())?;
    // The node's name carries the *memory* width and the operands keep the
    // register's -- `(atomic_load_add_i8 GPR64sp:$Rn, GPR32:$Rs)` is how a
    // byte atomic is written, in LLVM's own AArch64 backend as much as here.
    // Requiring the two to be equal declined every byte and halfword atomic on
    // the seed, 144 of them, for a mismatch that is not one.
    if rmw.access > root_width || !matches!(rmw.access, 8 | 16 | 32 | 64) {
        return Err(format!(
            "no SelectionDAG node for a {}-bit atomic into a {root_width}-bit register",
            rmw.access
        ));
    }
    let address = instruction
        .operands
        .iter()
        .find(|operand| operand.name == rmw.address)
        .ok_or_else(|| "the address is not an operand".to_string())?;
    let word_bits = document
        .isas
        .iter()
        .find(|isa| isa.name == instruction.isa)
        .map(|isa| isa.word_bits)
        .unwrap_or(address.width);
    if address.width != word_bits {
        return Err(format!(
            "the address is {} bits and the machine's word is {word_bits}",
            address.width
        ));
    }
    let (operation, operand) = atomicrmw_operation(&rmw.stored, &rmw.loaded);
    if operation == "unsupported" {
        return Err("the stored value is not an atomic operation".to_string());
    }
    let ordering = rmw
        .ordering()
        .ok_or_else(|| "no LLVM ordering for these halves".to_string())?;
    // `xchg` is `atomic_swap`; everything else is `atomic_load_<op>`.
    let node = if operation == "xchg" {
        format!("atomic_swap_i{}_{ordering}", rmw.access)
    } else {
        format!("atomic_load_{operation}_i{}_{ordering}", rmw.access)
    };
    let build = |expr: &SemanticExpr, width: u32| -> Result<String, String> {
        let sem = lower(&reduce_pattern_helpers(expr), width)
            .map_err(|error| format!("semantics did not lower: {}", error.message))?;
        sdnode_pattern_with(&fold_constant_arithmetic(&sem), width, leaf)
            .ok_or_else(|| "no SelectionDAG pattern for these operators".to_string())
    };
    let address_dag = build(&SemanticExpr::Atom(rmw.address.clone()), address.width)?;
    let operand_dag = build(&operand, root_width)?;
    // The root carries its type. The node's own name says the *memory* width;
    // what the pattern produces is a register, and a class holding more than
    // one value type -- which `rv_gpr` does, because the document names both
    // 32- and 64-bit operands of it -- leaves tblgen unable to infer either.
    let value_type = super::llvm_target::value_type(root_width);
    Ok(format!(
        "({value_type} ({node} {address_dag}, {operand_dag}))"
    ))
}

/// The SelectionDAG pattern for a store that also updates its base register.
///
/// LLVM spells these `pre_store`/`post_store` -- one result, the updated base,
/// and three operands: value, base, offset. They are the only writeback shape
/// TableGen can state: an indexed *load* produces two results, and a `Pat`
/// produces one, which is why those stay in `ISelDAGToDAG` C++.
///
/// The instruction side was already right. A post-index store has emitted
/// `(outs $RN), (ins $RT, $RN_tied, $IMM)` with `Constraints = "$RN =
/// $RN_tied"` since the writeback check was written; nothing had asked it for
/// a pattern.
pub(crate) fn llvm_indexed_store_pattern_dag(
    document: &Document,
    instruction: &Instruction,
    leaf: &PatternLeaf,
) -> Result<(String, String), String> {
    if !instruction.scalable_origin.is_empty() {
        return Err("a scalable instruction's operands are per-lane".to_string());
    }
    let indexed = crate::effects::indexed_store_semantics(instruction)
        .map_err(|reason| reason.unwrap_or_default())?;
    let value_width = store_value_width(instruction, &indexed.value)
        .ok_or_else(|| "the stored value is not a register operand".to_string())?;
    let base = instruction
        .operands
        .iter()
        .find(|operand| operand.name == indexed.base)
        .ok_or_else(|| "the base is not an operand".to_string())?;
    let word_bits = document
        .isas
        .iter()
        .find(|isa| isa.name == instruction.isa)
        .map(|isa| isa.word_bits)
        .unwrap_or(base.width);
    if base.width != word_bits {
        return Err(format!(
            "the address is {} bits and the machine's word is {word_bits}",
            base.width
        ));
    }
    let node = if indexed.access == value_width {
        if indexed.pre { "pre_store" } else { "post_store" }.to_string()
    } else if indexed.access < value_width && matches!(indexed.access, 8 | 16 | 32) {
        format!(
            "{}_truncsti{}",
            if indexed.pre { "pre" } else { "post" },
            indexed.access
        )
    } else {
        return Err(format!(
            "no SelectionDAG node for a {}-bit indexed store",
            indexed.access
        ));
    };

    let build = |expr: &SemanticExpr, width: u32| -> Result<String, String> {
        let sem = lower(&reduce_pattern_helpers(expr), width)
            .map_err(|error| format!("semantics did not lower: {}", error.message))?;
        let sem = fold_constant_arithmetic(&sem);
        sdnode_pattern_with(&sem, width, leaf)
            .ok_or_else(|| "no SelectionDAG pattern for these operators".to_string())
    };
    let value_dag = build(&indexed.value, value_width)?;
    let base_dag = build(&SemanticExpr::Atom(indexed.base.clone()), base.width)?;
    let offset_dag = build(&indexed.offset, base.width)?;
    let value_type = super::llvm_target::value_type(value_width);
    Ok((
        format!("({node} ({value_type} {value_dag}), {base_dag}, {offset_dag})"),
        indexed.base,
    ))
}

/// The width of the register a store's address is formed from.
fn address_register_width(instruction: &Instruction, addr: &SemanticExpr) -> Option<u32> {
    let mut widest = None;
    let mut stack = vec![addr];
    while let Some(node) = stack.pop() {
        match node {
            SemanticExpr::Atom(name) => {
                if let Some(operand) = instruction.operands.iter().find(|operand| {
                    operand.name == *name && register_class(&operand.kind).is_some()
                }) {
                    widest = Some(widest.map_or(operand.width, |seen: u32| seen.max(operand.width)));
                }
            }
            SemanticExpr::List(items) => stack.extend(items.iter()),
        }
    }
    widest
}

/// The width of the register a store writes to memory.
fn store_value_width(instruction: &Instruction, value: &SemanticExpr) -> Option<u32> {
    let SemanticExpr::Atom(name) = value else {
        return None;
    };
    instruction
        .operands
        .iter()
        .find(|operand| operand.name == *name && register_class(&operand.kind).is_some())
        .map(|operand| operand.width)
}

/// The scales in a store's address, found the same way a value's are.
pub(crate) fn scaled_store_immediates(instruction: &Instruction) -> Vec<(String, u32)> {
    let Ok((_, addr, _)) = crate::effects::pure_store_semantics(instruction) else {
        return Vec::new();
    };
    let Some(root_width) = store_root_width(instruction) else {
        return Vec::new();
    };
    let Ok(sem) = lower(&reduce_pattern_helpers(&addr), root_width) else {
        return Vec::new();
    };
    let is_immediate = |name: &str| {
        instruction
            .operands
            .iter()
            .any(|operand| operand.name == name && register_class(&operand.kind).is_none())
    };
    let mut found = Vec::new();
    collect_scaled(&sem, &is_immediate, &mut found);
    found
}

/// The width a store's pattern is typed at, for callers that need it before
/// building the DAG.
pub(crate) fn store_root_width(instruction: &Instruction) -> Option<u32> {
    let (value, _, _) = crate::effects::pure_store_semantics(instruction).ok()?;
    store_value_width(instruction, &value)
}

fn collect_pattern_symbols(sem: &Sem, out: &mut std::collections::HashSet<String>) {
    match sem {
        Sem::Call { args, .. } => args.iter().for_each(|(_, arg)| collect_pattern_symbols(arg, out)),
        Sem::Sym(name) => {
            out.insert(name.clone());
        }
        Sem::Int { .. } => {}
        Sem::App { args, .. } => args
            .iter()
            .for_each(|arg| collect_pattern_symbols(arg, out)),
        Sem::Ext { arg, .. } => collect_pattern_symbols(arg, out),
    }
}

/// Render a `Sem` node as a SelectionDAG pattern fragment, or `None` if any
/// node is width-inconsistent with `root_width` or uses an operator with no
/// clean SelectionDAG form. Operators become their ISD node names; constants
/// become typed immediates (`(i32 31)`); a leaf is spelled by the caller.
///
/// That last part is why this takes a closure. The intrinsic patterns type a
/// leaf by width (`i64:$rs1`); a pattern that selects a real instruction
/// types it by its register class (`GPRRegs:$rs1`). One builder, so the two
/// files cannot come to disagree about what an instruction means -- and
/// `llvm_target_check.py` checks that conclusion rather than trusting it.
pub(crate) fn sdnode_pattern_with(
    sem: &Sem,
    root_width: u32,
    leaf: &PatternLeaf,
) -> Option<String> {
    match sem {
        // A selection pattern cannot match a call: the instruction is not
        // selected this way, and stays out of the target's patterns.
        Sem::Call { .. } => None,
        Sem::Sym(name) => leaf(name, None, root_width),
        Sem::Int { value, width } => (*width == root_width).then(|| {
            // The signed bit pattern *at the pattern's width*, which is how
            // TableGen spells an integer literal. Truncating to 32 regardless
            // turned FSGNJ.D's magnitude mask into -1 and its sign mask into 0,
            // so the DAG reduced to `rs1` and the pattern told LLVM to select a
            // sign injection for any value at all. The LLVM IR emitter beside
            // this one switches on the width and always did; it is the one with
            // sixty gates behind it.
            let bits = root_width.clamp(1, 64);
            let raw = (*value as u64)
                & if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
            let signed = if bits >= 64 {
                raw as i64
            } else if raw >> (bits - 1) != 0 {
                (raw as i64) - (1i64 << bits)
            } else {
                raw as i64
            };
            // Typed, not bare. TableGen cannot always infer a constant's
            // type from context -- a shift amount is the usual case, since
            // LLVM does not tie it to the shifted value's type -- and reports
            // "Could not infer all types in pattern". Real backends write
            // `(i64 8)` for the same reason.
            format!("(i{bits} {signed})")
        }),
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => {
            if *width != root_width {
                return None;
            }
            // An extension applied directly to a *symbol* may not be a DAG
            // node at all. When the symbol is an encoded immediate, `(sext 12
            // imm)` is not an operation the selector performs -- it is the
            // range of the values the field can hold, which LLVM spells as a
            // predicate on the operand (`simm12:$imm`) and not as a node.
            // Spelling it as `sext_inreg` would also be untypeable: i12 is not
            // a legal MVT, which is exactly why every `addi`-shaped
            // instruction in the corpus had no pattern.
            //
            // The caller decides, because only it knows which symbols are
            // immediates. `None` means "not an immediate" and falls through to
            // the real DAG node below, which is what an extension of a
            // *register* is.
            if let (Sem::Sym(name), Op::Sext | Op::Zext) = (arg.as_ref(), op) {
                if let Some(spelled) =
                    leaf(name, Some((matches!(op, Op::Sext), *from_bits)), root_width)
                {
                    return Some(spelled);
                }
            }
            let inner = sdnode_pattern_with(arg, root_width, leaf)?;
            match op {
                // Sign-extend from the low `from_bits` — needs a standard VT token.
                Op::Sext => matches!(from_bits, 1 | 8 | 16 | 32)
                    .then(|| format!("(sext_inreg {inner}, i{from_bits})")),
                // Zero-extend from the low `from_bits` is a mask.
                Op::Zext => {
                    let mask = if *from_bits >= 32 {
                        u32::MAX
                    } else {
                        (1u32 << from_bits) - 1
                    };
                    Some(format!("(and {inner}, (i{root_width} {mask}))"))
                }
                _ => None,
            }
        }
        Sem::App { op, width, args } => {
            if *width != root_width {
                return None;
            }
            let parts = args
                .iter()
                .map(|arg| sdnode_pattern_with(arg, root_width, leaf))
                .collect::<Option<Vec<_>>>()?;
            // No `not` ISD node; the canonical DAG form is `(xor x, -1)`.
            if matches!(op, Op::Not) {
                return Some(format!("(xor {}, -1)", parts[0]));
            }
            let node = sdnode_name(*op)?;
            Some(format!("({node} {})", parts.join(", ")))
        }
    }
}

/// A shift amount narrowed to the width the node evaluates at.
fn llvm_shift_amount(
    amount: &str,
    width: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    if width >= word.bits {
        return amount.to_string();
    }
    let narrowed = llvm_fresh(counter);
    body.push_str(&format!(
        "  {narrowed} = and {} {amount}, {}\n",
        word.ty,
        (1u128 << width) - 1
    ));
    narrowed
}

fn sdnode_name(op: Op) -> Option<&'static str> {
    Some(match op {
        Op::Add => "add",
        Op::Sub => "sub",
        Op::Mul => "mul",
        Op::And => "and",
        Op::Or => "or",
        Op::Xor => "xor",
        Op::Shl => "shl",
        Op::Lshr => "srl",
        Op::Ashr => "sra",
        Op::Rol => "rotl",
        Op::Ror => "rotr",
        Op::Clz => "ctlz",
        Op::Ctz => "cttz",
        Op::Cpop => "ctpop",
        Op::MinS => "smin",
        Op::MaxS => "smax",
        Op::MinU => "umin",
        Op::MaxU => "umax",
        // Division has defined zero-divisor behavior that generic SelectionDAG
        // nodes do not preserve. `Not` is special-cased; extends are `Sem::Ext`.
        Op::Udiv | Op::Sdiv | Op::Urem | Op::Srem | Op::Not | Op::Select | Op::Sext
        | Op::Zext => return None,
        // A dynamic rounding mode is not a SelectionDAG pattern at all: the
        // constrained intrinsics take rounding as static metadata.
        Op::FaddRm | Op::FsubRm | Op::FmulRm | Op::FdivRm | Op::FsqrtRm
        | Op::FmaRm => return None,
        // The exceptions an operation raises are read from the floating-point
        // environment, which emitted IR cannot reach -- the same reason the
        // rounding-mode forms are withheld, one level along.
        Op::FaddFx | Op::FsubFx | Op::FmulFx | Op::FdivFx | Op::FsqrtFx
        | Op::FmaFx => return None,
        Op::FcvtF2SFx | Op::FcvtF2UFx | Op::FcvtS2FFx | Op::FcvtU2FFx
        | Op::FcvtF2FFx => return None,
        // A dynamic mask is a shift, a subtract and two selects, which is a
        // sequence rather than the single node a pattern matches.
        Op::Ones | Op::Zeros => return None,
        // A comparison produces an i1 that has to be widened, which is two
        // nodes rather than the one a pattern matches.
        Op::IcmpEq => "seteq",
        Op::IcmpNe => "setne",
        Op::IcmpSlt => "setlt",
        Op::IcmpSge => "setge",
        Op::IcmpUlt => "setult",
        Op::IcmpUge => "setuge",
        // `mulhs` and `mulhu` are ISD nodes that mean exactly what these
        // instructions compute. The MIXED form is the one with no node: a
        // signed multiplicand and an unsigned multiplier is a RISC-V idea and
        // SelectionDAG has no name for it.
        Op::Mulh => "mulhs",
        Op::Mulhu => "mulhu",
        Op::Mulhsu => return None,
        // Float arithmetic has clean ISD nodes, but AXIS's canonical-NaN rule
        // is not expressible in a SelectionDAG pattern, so a pattern would
        // claim more than the instruction guarantees.
        Op::Fadd
        | Op::Fsub
        | Op::Fmul
        | Op::Fdiv
        | Op::Fsqrt
        | Op::Fma
        | Op::Fneg
        | Op::FcmpOeq
        | Op::FcmpOlt
        | Op::FcmpOle
        | Op::FcmpUno
        | Op::FcvtF2S
        | Op::FcvtF2U
        | Op::FcvtS2F
        | Op::FcvtU2F
        | Op::FcvtF2F => return None,
    })
}
