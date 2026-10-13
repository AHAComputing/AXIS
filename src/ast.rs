#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub extension: Extension,
    pub isas: Vec<Isa>,
    pub formats: Vec<Format>,
    /// At most one mode selector (P2). Empty = the mode-free "one mode" world.
    pub modes: Vec<Mode>,
    pub configs: Vec<Config>,
    pub kernels: Vec<Kernel>,
    /// Memory-resident launch descriptors (`docs/accelerator_design.md`, H1b).
    pub descriptors: Vec<Descriptor>,
    /// MMIO devices: register maps whose accesses run handler instructions
    /// (`docs/accelerator_design.md`, H3).
    pub devices: Vec<Device>,
    pub instructions: Vec<Instruction>,
    /// Issue packets: statically scheduled slot rows (stage B1,
    /// `docs/vliw_spatial_design.md`). Empty = the single-issue world, which is
    /// the degenerate case of the group model rather than a special case in it.
    pub packets: Vec<Packet>,
    /// Explicit, validated source-sequence to target-instruction rewrites.
    pub lowerings: Vec<Lowering>,
    pub cores: Vec<Core>,
    pub personalities: Vec<Personality>,
    pub accelerators: Vec<Accelerator>,
    pub memories: Vec<Memory>,
    /// The fabrics memories talk over, and the memory systems built on them
    /// (`docs/memory_system_design.md`).
    pub interconnects: Vec<crate::memsys::Interconnect>,
    pub memsystems: Vec<crate::memsys::MemSystem>,
    pub tiles: Vec<Tile>,
    /// Spatial fabrics: grids of PEs and the links between them (stage G1).
    pub fabrics: Vec<Fabric>,
    /// Mappings: placements and routings onto a fabric (stage G2).
    pub mappings: Vec<Mapping>,
    pub channels: Vec<Channel>,
    /// Calling conventions (stage L4). An ABI is not derivable from an
    /// instruction set -- which register holds the first argument is a property
    /// of a platform, not of a machine -- so it is *declared*, and what AXIS
    /// decides is whether the declaration is consistent with itself.
    pub abis: Vec<Abi>,
    /// Description-defined functions (`deffun`): emitted once by every backend
    /// and CALLED, never inlined -- an S-box, a cipher round, Arm's FMAX. A
    /// `defsem` is pasted where it is used, and every backend pastes a bound
    /// value's text too, so nested uses grew exponentially (FMAXV.H rendered
    /// to 142 MB of C). A call stays the size of its arguments.
    pub functions: Vec<Function>,
}

/// One `deffun`: pure, scalar, non-recursive. Its body may call other
/// functions; calls appear in semantics as `(call name iR (iP arg) ...)`, each
/// argument carrying the width its parameter reads it at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    pub params: Vec<(String, u32)>,
    pub result_width: u32,
    pub body: crate::semantics::SemanticExpr,
}

/// One register, or a run of them, named the way an ABI names registers: by
/// class and index. AXIS's register files are classes with counts rather than
/// individually named registers, so `(rv_gpr 10 17)` is how a description says
/// "a0 through a7" without inventing per-register names the machine does not
/// have.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RegisterRef {
    pub class: String,
    pub first: u32,
    /// Inclusive. Equal to `first` for a single register.
    pub last: u32,
}

impl RegisterRef {
    pub fn indices(&self) -> impl Iterator<Item = u32> + '_ {
        self.first..=self.last
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Abi {
    pub name: String,
    pub isa: String,
    pub pointer_bits: u32,
    pub stack_alignment: u32,
    /// Reserved by definition: an allocatable stack pointer is not one.
    pub stack_pointer: Option<RegisterRef>,
    /// Callee-saved by definition: a frame pointer the callee does not
    /// preserve is not a frame pointer.
    pub frame_pointer: Option<RegisterRef>,
    pub link_register: Option<RegisterRef>,
    pub arguments: Vec<RegisterRef>,
    pub returns: Vec<RegisterRef>,
    /// These three partition every register of every class the ABI names.
    /// A register in none of them is one a compiler cannot know whether to
    /// save; a register in two is a contradiction.
    pub callee_saved: Vec<RegisterRef>,
    pub caller_saved: Vec<RegisterRef>,
    pub reserved: Vec<RegisterRef>,
    /// The stack frame (stage F1), if this ABI states one.
    pub frame: Option<Frame>,
    /// How aggregates are passed (stage F3), if this ABI states it.
    pub aggregates: Option<Aggregates>,
    pub description: String,
}

/// The relation between an encoded field and the number the assembly prints.
///
/// Both forms are affine with a unit coefficient, so both are bijections on the
/// integers and both invert without division or rounding. That is the whole
/// selection rule: an assembler reading the published description has to be
/// able to run it backwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AsmTransform {
    /// The assembly prints the field itself.
    #[default]
    Identity,
    /// The assembly prints `k - field`, and an assembler recovers the field as
    /// `k - printed`. Self-inverse. AArch64's fixed-point `fbits`.
    MinusFrom(u32),
    /// The assembly prints `field + k`, recovered as `printed - k`. The other
    /// common shape: a field that stores a count one less than it names.
    Plus(u32),
}

impl AsmTransform {
    /// The number the assembly prints for this encoded field.
    pub fn print(self, field: u64) -> i64 {
        match self {
            Self::Identity => field as i64,
            Self::MinusFrom(k) => i64::from(k) - field as i64,
            Self::Plus(k) => field as i64 + i64::from(k),
        }
    }

    /// The field an assembler must encode for this printed number, going back.
    pub fn encode(self, printed: i64) -> i64 {
        match self {
            Self::Identity => printed,
            Self::MinusFrom(k) => i64::from(k) - printed,
            Self::Plus(k) => printed - i64::from(k),
        }
    }

    /// How this is written in a description, or `None` for the default.
    pub fn lisp(self) -> Option<String> {
        match self {
            Self::Identity => None,
            Self::MinusFrom(k) => Some(format!("(asm (minus-from {k}))")),
            Self::Plus(k) => Some(format!("(asm (plus {k}))")),
        }
    }
}

/// How a laid-out aggregate is *passed*. Not how it is laid out: padding,
/// bitfields and nested alignment are the source language's rule, not the
/// machine's, and they belong to whoever defines that language.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Aggregates {
    /// Larger than this passes by reference. A threshold no set of argument
    /// registers can hold is one that passes nothing by value.
    pub max_register_bytes: u32,
    /// `allowed` or `forbidden`: may an aggregate straddle the last register
    /// and the stack.
    pub split: String,
    /// Where the caller puts the address of the space a returned aggregate is
    /// written into. Passed like an argument, so it has to be one.
    pub return_pointer: Option<RegisterRef>,
}

/// How a callee establishes its frame. Declared, not inferred -- which end the
/// saved registers live at is a platform choice, not a property of the machine
/// -- but the declaration is arithmetic over registers the ABI already named
/// and offsets the instruction set already knows how to encode, so it can be
/// held to a good deal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Frame {
    /// `down` or `up`: which way the stack pointer moves on a call.
    pub growth: String,
    /// `top` or `bottom`: which end of the frame the saved registers occupy.
    pub saved_area: String,
    pub slot_bytes: u32,
    /// The saved registers, first at the outermost slot. Order is the content
    /// of the layout, so it is a sequence rather than a set.
    pub save_order: Vec<RegisterRef>,
    /// `incoming-sp` or `frame-base`: what the frame pointer holds.
    pub frame_pointer_at: String,
    /// The largest frame this platform allows. What makes it checkable rather
    /// than decorative is that `save` has to be able to reach the top of it.
    pub max_frame_bytes: u32,
    /// Bytes below the stack pointer a leaf may use without adjusting it.
    pub red_zone: u32,
    /// The instructions that establish and tear down the frame. Named, then
    /// checked to be what they claim.
    pub adjust: String,
    pub save: String,
    pub restore: String,
    /// The frame's regions, lowest address first (stage F4). Sizes are absent
    /// on purpose: how many spill slots a function needs and how large its
    /// locals are is the register allocator's decision, made per function at
    /// compile time, and a description that stated it would be stating
    /// something it cannot know. The *order* is the platform's, and it is what
    /// a consumer needs to place anything at all.
    pub regions: Vec<String>,
    /// What one register of a class costs when it is spilled (F4). Machine
    /// data: a 128-bit vector needs sixteen bytes wherever it is put.
    pub spill: Vec<SpillSlot>,
    /// `allowed` or `forbidden`: may a function align its frame more strongly
    /// than the ABI does (stage F5).
    pub realignment: String,
    /// `allowed` or `forbidden`: may the stack pointer move inside the body.
    pub dynamic_allocation: String,
    /// The register holding the frame base when neither the stack pointer nor
    /// the frame pointer can. Required exactly where both of the above are
    /// allowed -- see `validate_frame_discipline`.
    pub base_pointer: Option<RegisterRef>,
}

/// What one register of a class costs in the spill region. Not where it goes:
/// that is the allocator's, per function.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpillSlot {
    pub class: String,
    pub bytes: u32,
    pub align: u32,
}

impl Frame {
    /// Where one saved register sits, as a byte offset from the frame base --
    /// the stack pointer after the adjustment. The layout is a function, and
    /// this is it; nothing else in the repository is allowed a second copy.
    pub fn slot(&self, rank: usize, frame_bytes: u32) -> u32 {
        let rank = rank as u32;
        if self.saved_area == "top" {
            frame_bytes - (rank + 1) * self.slot_bytes
        } else {
            rank * self.slot_bytes
        }
    }

    /// The bytes the saved area occupies.
    pub fn saved_bytes(&self) -> u32 {
        self.save_order
            .iter()
            .map(|entry| entry.last - entry.first + 1)
            .sum::<u32>()
            * self.slot_bytes
    }

    /// Every saved register, flattened out of the ranges that named them, in
    /// the order they are saved.
    pub fn saved_registers(&self) -> Vec<(String, u32)> {
        self.save_order
            .iter()
            .flat_map(|entry| entry.indices().map(|index| (entry.class.clone(), index)))
            .collect()
    }
}

impl Default for Document {
    fn default() -> Self {
        Self {
            extension: Extension::default(),
            isas: Vec::new(),
            formats: Vec::new(),
            modes: Vec::new(),
            configs: Vec::new(),
            kernels: Vec::new(),
            descriptors: Vec::new(),
            devices: Vec::new(),
            instructions: Vec::new(),
            packets: Vec::new(),
            lowerings: Vec::new(),
            cores: Vec::new(),
            personalities: Vec::new(),
            accelerators: Vec::new(),
            memories: Vec::new(),
            interconnects: Vec::new(),
            memsystems: Vec::new(),
            tiles: Vec::new(),
            fabrics: Vec::new(),
            mappings: Vec::new(),
            channels: Vec::new(),
            abis: Vec::new(),
            functions: Vec::new(),
        }
    }
}

/// One field of an instruction format: a named slice of instruction bits.
/// `op_hi`/`op_lo` optionally bind a sub-slice of an operand's value to this
/// field (for scattered immediates such as RISC-V S/B/J types); plain fields
/// bind the operand (or fixed encoding value) starting at bit 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatField {
    pub name: String,
    pub insn_hi: u32,
    pub insn_lo: u32,
    pub op_hi: Option<u32>,
    pub op_lo: Option<u32>,
}

impl FormatField {
    pub fn width(&self) -> u32 {
        self.insn_hi - self.insn_lo + 1
    }
}

/// A named instruction bit layout. Instructions reference formats by name;
/// fields resolve to fixed encoding values or operand bindings by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    pub name: String,
    pub bits: u32,
    pub fields: Vec<FormatField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub name: String,
    pub version: String,
    pub target: String,
    pub description: String,
}

impl Default for Extension {
    fn default() -> Self {
        Self {
            name: String::new(),
            version: "1.0".to_string(),
            target: "rvmt".to_string(),
            description: String::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Isa {
    pub name: String,
    /// Optional translation role: `source` instructions are lifted and matched
    /// to semantically equivalent instructions in a `target` ISA.
    pub role: String,
    pub base: String,
    pub word_bits: u32,
    pub registers: Vec<String>,
    pub features: Vec<String>,
    pub memory_model: String,
    pub endianness: String,
    /// How many lanes execute one instruction, for an ISA that is lane-parallel
    /// in its EXECUTION rather than in its register layout.
    ///
    /// `vector_bits` says how wide a vector REGISTER is, which is the right
    /// question for SVE and RVV and the wrong one for a SIMT machine: GRV's
    /// registers are ordinary per-lane scalars and the lanes come from the
    /// machine executing one instruction stream N ways. Declaring it makes the
    /// lane index a first-class readable value (`lane_id`) rather than a slot
    /// each such ISA has to invent a name for, and — because it is a scalar
    /// state read rather than a `vni` value — it does NOT instantiate the
    /// instruction into a lane group, which is what an encoding-surface
    /// consumer cannot carry.
    ///
    /// Zero means "this ISA does not declare lanes", and referencing `lane_id`
    /// is then an error rather than a default.
    pub lanes: u32,
    /// How lanes this ISA declares unspecified are realised: `compute`, `ones`
    /// or `zeros`. The ladder runs each in turn and requires defined lanes to
    /// agree under all of them.
    pub unspecified_realization: String,
    /// Which order a reduction the architecture leaves unordered is realised
    /// in: `sequential` or `pairwise`. Empty means sequential, which is what
    /// every document meant before the knob existed — so a document that does
    /// not declare it emits what it emitted before.
    ///
    /// A knob rather than a fixed choice because the architecture's claim is
    /// that *either* is correct, and a ladder that pins one proves agreement
    /// with a decision the machine never made. The sweep is
    /// `tools/reduction_order_check.py`.
    pub reduction_realization: String,
    /// The `vtype` point this document is elaborated at (stage S3). SEW is the
    /// element width and LMUL the rational register footprint; both come from a
    /// CSR on a real machine, and both must be static here because they decide
    /// shapes. Zero SEW means the document uses no `vtype`-derived atom.
    pub vector_sew: u32,
    pub vector_lmul_num: u32,
    pub vector_lmul_den: u32,
    /// The widest element the machine supports; `SEW <= ELEN` is what makes
    /// most of the (SEW, LMUL) cross product illegal.
    pub vector_elen: u32,
    /// Vector length in bits for scalable vectors (`docs/scalable_vectors_design.md`).
    /// Zero means the ISA declares none, and scalable type atoms are then an
    /// error rather than silently instantiating at some default.
    pub vector_bits: u32,
}

impl Default for Isa {
    fn default() -> Self {
        Self {
            name: String::new(),
            role: String::new(),
            base: "rv32i".to_string(),
            word_bits: 32,
            registers: Vec::new(),
            features: Vec::new(),
            memory_model: "rvwmo".to_string(),
            vector_bits: 0,
            lanes: 0,
            vector_sew: 0,
            vector_lmul_num: 1,
            vector_lmul_den: 1,
            vector_elen: 64,
            unspecified_realization: String::new(),
            reduction_realization: String::new(),
            endianness: "little".to_string(),
        }
    }
}

/// The reserved `implementation` answer meaning *nobody* performs this
/// instruction here.
///
/// An instruction says who performs it in one of three ways: it states
/// semantics, and AXIS says what it computes; it names a routine, and the
/// embedder says; or it says this word, and nothing does -- an executor that
/// meets one traps with [`UNSUPPLIED_TRAP`] rather than calling anything.
///
/// That third state is a claim about the ARTIFACT, not the machine. `PACIZA`
/// does not trap on hardware; it computes a signature this description cannot
/// state. Recording that the answer is missing *here* is a different fact from
/// "this instruction traps", and keeping the two apart is the whole reason the
/// state exists rather than being written as a behavior that traps.
pub const UNSUPPLIED: &str = "unsupplied";

/// The cause an executor reports when it meets an unsupplied instruction.
///
/// Deliberately not one of the architectural causes -- `illegal`, `ecall`,
/// `ebreak`, `misaligned`, `access` -- because it is not one of them: those say
/// what the machine does, and this says what this build of the executor cannot.
pub const UNSUPPLIED_TRAP: &str = "unimplemented";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub name: String,
    pub mnemonic: String,
    /// ISA/encoding space this instruction belongs to. Empty preserves the
    /// legacy extension-wide instruction model; translation documents should
    /// bind source and target instructions explicitly.
    pub isa: String,
    pub description: String,
    pub category: String,
    pub format: String,
    pub opcode: u32,
    pub func3: u32,
    pub func7: u32,
    pub operands: Vec<Operand>,
    /// Explicit fixed-field values for the instruction's format, e.g.
    /// `encoding: [opcode=0x0b, func3=0x3, func2=0]`. Entries override the
    /// flat `opcode`/`func3`/`func7` sugar fields.
    pub encoding: Vec<(String, u32)>,
    pub asm: String,
    pub semantics: String,
    /// Optional OptiSynth s-expression form of the instruction's
    /// semantics — e.g. `(add i32 (mul i32 a b) c)` for an FMA.
    /// When present, the AHA/OptiSynth bridge derives a Z3 axiom
    /// and a verified rewrite rule from this field automatically.
    /// Empty string means "not provided"; downstream tools may
    /// fall back to the free-text `semantics` field.
    pub formal_semantics: String,
    /// The lane-wise spelling this instruction was written with, before
    /// `simd::expand_vector_text` rewrote it into bit-vector operations —
    /// empty when it used no vector operators.
    ///
    /// `formal_semantics` stays the expansion, so every backend and gate keeps
    /// working unchanged and the expansion remains the proven definition of what
    /// a lane-wise operator means. This field exists for backends that have
    /// native vector types (LLVM's `<N x iW>`) and can emit the structure
    /// directly; being derived from the expansion's own input rather than
    /// written twice, it cannot drift from it.
    pub vector_semantics: String,
    /// For a lane of an instantiated scalable instruction, the mnemonic it came
    /// from; empty for everything else.
    ///
    /// Lanes of one scalable instruction share an encoding because a machine
    /// issues *one* instruction that does every lane — they are not
    /// alternatives competing for a bit pattern. Recording the origin lets the
    /// decode-disjointness check say that precisely, instead of the corpus
    /// inventing distinct encodings that would put a falsehood in the decode
    /// tables.
    pub scalable_origin: String,
    /// Which lane of `scalable_origin` this instruction is.
    pub scalable_lane: u32,
    /// For a lane whose result is only partly specified, the mnemonic of the
    /// instruction computing *which* of it is defined (stage S2, mechanism M1).
    /// Empty means the result is defined in full.
    ///
    /// The mask is a separate ordinary instruction rather than a second return
    /// value, so every backend computes it with machinery that already exists
    /// and the existing backend-vs-golden gates already prove they agree on it.
    pub defined_by: String,
    /// Set on the mask instruction itself, naming the instruction whose
    /// definedness it computes.
    ///
    /// A mask shares its instruction's encoding by construction -- it is a
    /// second view of one word, not a second instruction. Consumers that
    /// enumerate what a word decodes to have to tell the two apart, and doing
    /// it by the `__defined` suffix is reading a name where a fact belongs.
    pub definedness_of: String,
    /// The operand that decides which lanes of this instruction are defined:
    /// an active length under `vtail`, a predicate under `vundef`. Published
    /// because a consumer that wants to *reach* an undefined lane must drive
    /// this operand into a narrow range; guessing which operand it is from its
    /// name is the re-derivation that vacuous gates are made of.
    pub defined_operand: String,
    /// Compatibility source text for the legacy infix effect surface, or the
    /// canonical rendering produced by the Lisp frontend. A pure single
    /// register `set` also desugars into `formal_semantics`.
    pub effects: String,
    /// Canonical typed behavior, populated once by the source frontend.
    /// Backends consume this field directly; `effects` is retained only as
    /// compatibility source text and for diagnostics/reflection.
    pub behavior: Option<crate::effects::Behavior>,
    /// Optional operand-dependent decode legality predicate. Match/mask is
    /// evaluated first; a matching word is only an instruction when this
    /// predicate also holds.
    pub decode_requires: String,
    /// Canonical legality tree populated once by the source frontend.
    /// `decode_requires` remains compatibility source/reflection text.
    pub decode_constraint: Option<crate::decode_constraint::DecodeConstraint>,
    /// Mode names in which this instruction is legal (P2). Empty = legal in all
    /// modes (the mode-free default keeps output byte-identical).
    pub modes: Vec<String>,
    /// The functional-unit class that executes this instruction (stage B1).
    /// Empty = the single implicit unit, which is what every document without
    /// packets means.
    ///
    /// Slot legality is *derived* from this: an instruction may occupy slot `k`
    /// iff its unit is in slot `k`'s unit set. Declaring it per slot instead
    /// would need one instruction per slot, and one semantics written as many.
    pub unit: String,
    /// The mapping this instruction launches, for a machine whose array is
    /// entered by an instruction rather than by a mode bit alone.
    ///
    /// The instruction's operands supply the mapping's live-ins and receive its
    /// live-outs, and its semantics must be the mapping's scalar order
    /// composed. That is what ties the two halves together: the ordinary
    /// executor gates prove the instruction against the golden model, G3 proves
    /// the mapping computes its scalar order, and the composition check proves
    /// the instruction and the mapping are talking about the same computation.
    /// None of the three sees the other's evidence.
    pub runs_mapping: String,
    pub latency_cycles: u32,
    pub throughput_per_cycle: String,
    pub area_estimate_um2: String,
    pub power_estimate_mw: String,
    pub expected_speedup: String,
    pub intrinsic: String,
    /// A routine the embedder supplies that PERFORMS this instruction.
    ///
    /// For an instruction whose semantics are undecided, deferred, or genuinely
    /// unexpressible -- pointer authentication, a breakpoint, anything whose
    /// answer lives outside the machine this describes -- and only for those:
    /// naming a routine says what to call, not what it computes.
    ///
    /// So consumers that RUN code may call it, and consumers that REASON about
    /// code must not. The C executor and the stencil JIT it feeds can; the
    /// golden model and SMT cannot, because a reference that defers to an
    /// opaque routine has stopped being a reference.
    pub implementation: String,
    pub patterns: Vec<String>,
    pub applicable_patterns: Vec<String>,
    pub rationale: String,
    /// The memory-resident configuration this instruction establishes
    /// (`docs/tensor_design.md`, T5). Naming it is what lets validation
    /// require the loads and the declared layout to agree; without it the
    /// declaration would be a comment beside the semantics.
    /// `(runs-kernel <name> <operand>...)`: the kernel this instruction
    /// launches and the operands its parameters bind to, name first.
    pub runs_kernel: Vec<String>,
    /// The kernel's expansion under that binding, as canonical effect text.
    /// When the instruction also states its own behavior the two must agree
    /// (the composition check); when it does not, this IS its behavior.
    pub kernel_effects: String,
    /// True when the behavior came from the kernel rather than the source,
    /// so the canonical form re-emits the launch and not the expansion.
    pub behavior_from_kernel: bool,
    /// `(launches <descriptor> <base> <kernel> <argument>...)`: the descriptor
    /// this instruction reads at the address in `<base>`, and the kernel it
    /// runs over the descriptor's fields. Its behavior is derived: the kernel
    /// guarded by every check, then one status write.
    pub launches: Vec<String>,
    /// True when the behavior came from a descriptor launch, so the canonical
    /// form re-emits the launch and not the expansion.
    pub behavior_from_launch: bool,
    pub configures: String,
}

impl Default for Instruction {
    fn default() -> Self {
        Self {
            name: String::new(),
            mnemonic: String::new(),
            isa: String::new(),
            runs_mapping: String::new(),
            description: String::new(),
            category: "custom".to_string(),
            format: "R".to_string(),
            opcode: 0,
            func3: 0,
            func7: 0,
            operands: Vec::new(),
            encoding: Vec::new(),
            asm: String::new(),
            semantics: String::new(),
            formal_semantics: String::new(),
            vector_semantics: String::new(),
            scalable_origin: String::new(),
            scalable_lane: 0,
            defined_by: String::new(),
            definedness_of: String::new(),
            defined_operand: String::new(),
            effects: String::new(),
            behavior: None,
            decode_requires: String::new(),
            decode_constraint: None,
            modes: Vec::new(),
            unit: String::new(),
            latency_cycles: 1,
            throughput_per_cycle: "1.0".to_string(),
            area_estimate_um2: "0.0".to_string(),
            power_estimate_mw: "0.0".to_string(),
            expected_speedup: "1.0".to_string(),
            intrinsic: String::new(),
            implementation: String::new(),
            patterns: Vec::new(),
            applicable_patterns: Vec::new(),
            rationale: String::new(),
            runs_kernel: Vec::new(),
            kernel_effects: String::new(),
            behavior_from_kernel: false,
            launches: Vec::new(),
            behavior_from_launch: false,
            configures: String::new(),
        }
    }
}

/// A symbolic operand value in an explicit lowering pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweringValue {
    /// A named value/register identity shared across source and target steps.
    Variable(String),
    /// A fixed encoded operand value.
    Literal(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringBinding {
    pub operand: String,
    pub value: LoweringValue,
}

/// One instruction application in a lowering pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringStep {
    /// Instruction mnemonic (resolved case-insensitively during validation).
    pub instruction: String,
    pub bindings: Vec<LoweringBinding>,
}

/// A side condition over symbolic lowering bindings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoweringPredicate {
    Compare {
        lhs: LoweringValue,
        op: crate::decode_constraint::CompareOp,
        rhs: LoweringValue,
    },
    And(Vec<LoweringPredicate>),
    Or(Vec<LoweringPredicate>),
    Not(Box<LoweringPredicate>),
}

/// An explicit sequence rewrite. Validation proves the source composition and
/// target instruction have identical typed value semantics and ordered named
/// architectural-state/memory effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lowering {
    pub name: String,
    pub sources: Vec<LoweringStep>,
    pub target: LoweringStep,
    pub requires: Option<LoweringPredicate>,
    pub source_cycles: u32,
    pub target_cycles: u32,
    pub benefit: String,
}

/// How one register class reads and writes, for the backends that generate
/// register access code.
///
/// The rules used to be written inline in each of them — the Python executor,
/// the C wide executor, the Rust wide executor, the JIT block builder — which
/// meant adding an ISA meant editing every one and hoping they agreed. RISC-V
/// arrived needing exactly one new rule (`x0` reads zero and discards writes)
/// and that is now a row here rather than a clause in four languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterClass {
    pub name: &'static str,
    /// An index that reads as zero and whose writes are discarded — AArch64's
    /// `XZR`/`WZR` at 31, RISC-V's `x0`.
    pub zero_index: Option<u32>,
    /// An index that names a state slot instead of the register file, and the
    /// slot it names. AArch64 encodes SP as 31 in the classes that have one.
    pub alias: Option<(u32, &'static str)>,
    /// Which STORAGE this class views.
    ///
    /// ⚠️ Not `lowering_family`, which is about which operands a lowering may
    /// bind to one variable -- x86's `x86_r32` and `x86_r64` deliberately have
    /// different families, so a 32-bit operand cannot bind a 64-bit variable,
    /// and they are nonetheless the same registers. Nothing said so. The first
    /// thing that asked was an overlap check over the derived layout, which
    /// reported `x86_r8hi` colliding with `x86_r64` -- correctly, on the
    /// evidence it had, about the one pair in the table that is supposed to
    /// collide.
    ///
    /// Two classes that name one file are views of one another and share
    /// slots on purpose. Two that do not, and overlap anyway, are a
    /// description in which writing `f0` changes `v16`.
    pub file: &'static str,
    /// Which classes a lowering may bind to one variable. Two operands can
    /// name one variable in a `deflowering` when their classes agree here --
    /// AArch64's `X`, `W`, and their SP-aliasing forms are one integer file,
    /// and a translation target's `reg` is the file it maps onto.
    ///
    /// This was a `match` on five class names inside the lowering validator,
    /// which meant a new view of an existing file was incompatible with the
    /// file it is a view of: `reg32` could not be added because nothing said
    /// it was still `reg`. A property of a class belongs in the table with the
    /// class, and this is the seventh vocabulary in this codebase to have been
    /// a list of names somewhere else first.
    pub lowering_family: &'static str,
    /// The width of the register file this class indexes, when the file has a
    /// width of its own rather than the ISA's word.
    ///
    /// Most classes leave this `None`: `rv_gpr` is as wide as XLEN, so a
    /// description says so with the operand's type atom and the ISA's own
    /// register declaration is what an operand is checked against.
    ///
    /// RISC-V's `f` file is not like that. FLEN is set by which extensions are
    /// present, not by XLEN -- with `D`, `f0`-`f31` are 64 bits on RV32 just
    /// as on RV64, which is why a single is *NaN-boxed* into the high bits
    /// rather than stored narrow. A class that took its width from the ISA
    /// word would have to call RV32's `f` registers 32 bits and then let
    /// `FADD.D` name 64 of them.
    ///
    /// It earns its place: the width rule exempted every class at a nonzero
    /// offset, because a second file had no declared width to be checked
    /// against. Under that exemption RV32's F instructions named 32-bit `f`
    /// registers and its D instructions named 64-bit ones -- the same file, at
    /// two widths, in one description -- and every gate passed, because the
    /// executors store 64-bit slots whatever the description claims.
    pub file_width: Option<u32>,
    /// The architectural width a read exposes, when narrower than the file —
    /// AArch64's W view of an X register.
    pub view_width: Option<u32>,
    /// Where this view starts within the register. Zero for every view that
    /// begins at the low bit; 8 for x86's `AH`, `element * width` for a vector
    /// element.
    ///
    /// Without this a view can only be a prefix, which is why `AH` has never
    /// been describable.
    pub view_offset: u32,
    /// What a write does to the bits this view does not cover.
    ///
    /// The two are genuinely different architectures rather than a preference:
    /// writing AArch64's `W0` zeroes the upper half of `X0`, while writing
    /// x86's `AL` preserves the upper 56 bits of `RAX` — and x86 does *both*,
    /// since writing `EAX` zeroes. A class that only masks-and-overwrites can
    /// express the first and not the second.
    pub write_policy: WritePolicy,
    /// How many slots one register of this class occupies.
    ///
    /// A slot is 64 bits, so a 128-bit vector register is two limbs and a
    /// 512-bit one is eight. This is what makes the ceiling go away rather than
    /// move: a wider register is more limbs, not a wider type, so nothing has to
    /// grow when VL does.
    ///
    /// Values stay within one limb regardless — under lane-indexed
    /// instantiation an operation is always on one element — so a *view* spans
    /// at most two limbs, and stitching never needs a loop.
    pub limbs: u32,
    /// Where this class starts in the flat register file.
    ///
    /// An architecture with more than one register file — RISC-V's `f0`–`f31`
    /// are distinct from `x0`–`x31`, and `FMV.X.W` moves between them — is
    /// modelled by giving each file a base, so `f5` is index 37 in one array.
    /// That keeps every executor's single register array, which is the reason
    /// this is an offset rather than a second array threaded through five ABIs.
    pub offset: u32,
    /// How many registers of this file's *own* stride precede it.
    ///
    /// `offset` is in slots, which is enough while the file below is scalar.
    /// It is not enough above a scalable file, whose size is `registers *
    /// VL/64` and therefore moves with VL: a predicate file placed at a fixed
    /// slot would sit inside the vector file at one VL and above it at
    /// another. Counted in registers, it stays where it is.
    pub index_offset: u32,
    /// How many registers a lane group advances per full register of
    /// elements. 1 for every contiguous group (RVV's LMUL). SME's ZA tiles
    /// are INTERLEAVED views of one array: row i of ZA<n>.S is ZA row 4i+n,
    /// of ZA<n>.D row 8i+n, of ZA<n>.H row 2i+n, of ZA0.B row i. With a ZA
    /// "register" being one row, that is this step, and nothing else about
    /// placement changes (`docs/accelerator_design.md`, S2).
    pub group_step: u32,
}

/// What a write does to the bits outside a narrow view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WritePolicy {
    /// They become zero. AArch64's `W` view, x86's `EAX`.
    Zero,
    /// They keep their value. x86's `AL`, `AH` and `AX`, and every vector
    /// element insert.
    Preserve,
}

/// Every register class the language knows.
///
/// `reg` is the plain one: every index is an ordinary register. The rest carry
/// an architecture's rules about which indices are special.
pub const REGISTER_CLASSES: &[RegisterClass] = &[
    // The low half of `reg`, for a machine whose word is 64 bits and whose
    // 32-bit operations write only 32 of them. AArch64 says this with
    // `a64_gpr32`; the translation target was saying it by naming `reg` at
    // width 32, which claims the register is 32 bits rather than that this
    // *view* of it is. It shares `reg`'s lowering family, which is what lets a
    // guest `W` operand and a native 32-bit operand bind one variable.
    RegisterClass { name: "reg32", file: "reg", lowering_family: "reg", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "reg", file: "reg", lowering_family: "reg", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    // A 128-bit register, two slots wide. ⚠️ `reg` is one limb, and two corpora
    // declared `i128` operands in it: the value did not fit, and the executor
    // -- which sizes a wide write from the operand's width -- wrote past the
    // register into its neighbour. `VADD_4S vd=1` wrote regs[1] and regs[2],
    // and regs[2] was its own source operand. Validation refuses that pairing
    // now, and this is what those descriptions should have named.
    RegisterClass { name: "reg128", file: "reg128", lowering_family: "reg", file_width: Some(128), zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "a64_gpr64", file: "reg", lowering_family: "reg", file_width: None, zero_index: Some(31), alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "a64_gpr32", file: "reg", lowering_family: "reg", file_width: None, zero_index: Some(31), alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "a64_gpr64sp", file: "reg", lowering_family: "reg", file_width: None, zero_index: None, alias: Some((31, "sp")), view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "a64_gpr32sp", file: "reg", lowering_family: "reg", file_width: None, zero_index: None, alias: Some((31, "sp")), view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    // AArch64's vector registers. A separate file above the general-purpose
    // one, for the reason `rv_fpr` is: `d0` is not `x0`, and it has no
    // hardwired zero.
    //
    // `V` is 128 bits architecturally, and `q0` and `d0` have to *be* one
    // register: `ldr q0` then `fadd d0` reads what the load wrote. So both
    // classes sit at one slot per register and name one `lowering_family` --
    // the `reg32`-beside-`reg` case, where nothing saying "still the same
    // file" made a view incompatible with the file it views.
    //
    // Two limbs of 64, not one slot holding 128. A single wide slot works only
    // where integers are arbitrary precision; the generated C and Rust compute
    // in machine words, and limbs are what they already have for this. So the
    // file is 64 slots for 32 registers, and `a64_vreg64` is the low limb's
    // view of it rather than a 64-bit file of its own.
    //
    // Writing `D` zeroes the upper half, which is what `WritePolicy::Zero`
    // over 128-bit storage says and what the architecture does. It carried
    // that policy before over 64-bit storage, where it had nothing to zero.
    RegisterClass { name: "a64_vreg64", file: "a64_vreg", lowering_family: "a64_vreg64", file_width: Some(64), zero_index: None, alias: None, view_width: Some(64), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 2, offset: 32, index_offset: 0, group_step: 1 },
    RegisterClass { name: "a64_vreg128", file: "a64_vreg", lowering_family: "a64_vreg64", file_width: Some(128), zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 2, offset: 32, index_offset: 0, group_step: 1 },
    // RISC-V: x0 is hardwired to zero in every base ISA, and there is no
    // second view of the register file, so one class covers RV32 and RV64 —
    // the width comes from the operand's type atom.
    RegisterClass { name: "rv_gpr", file: "rv_gpr", lowering_family: "rv_gpr", file_width: None, zero_index: Some(0), alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    // The C extension's three-bit register fields, which name `x8`-`x15` and
    // nothing else -- eight registers a compressed instruction can reach, so
    // the common ones fit in sixteen bits. `index_offset` is what says the
    // field's 0 is the file's 8; the family is `rv_gpr` because it *is* that
    // file, and a view of a file that did not say so would be incompatible
    // with it. There is no hardwired zero among x8-x15, so none is declared.
    RegisterClass { name: "rv_gpr_c", file: "rv_gpr", lowering_family: "rv_gpr", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 8, group_step: 1 },
    // SME's slice-index register: MOVA and the ZA loads name W12-W15 in a
    // two-bit field, so the operand reads register 12 + field, as a W view.
    RegisterClass { name: "a64_w12", file: "reg", lowering_family: "reg", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 12, group_step: 1 },
    // The F and D extensions' registers are a separate file: f0 is not x0, and
    // f0 is an ordinary register with no hardwired zero. It lives above the
    // integer file in the flat array.
    RegisterClass { name: "rv_fpr", file: "rv_fpr", lowering_family: "rv_fpr", file_width: Some(64), zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 0, group_step: 1 },
    // The C extension's window into the FP file: `f8`-`f15`, the same eight
    // registers its integer forms reach, and for the same reason -- three bits
    // is what a sixteen-bit instruction can spare for a register.
    RegisterClass { name: "rv_fpr_c", file: "rv_fpr", lowering_family: "rv_fpr", file_width: Some(64), zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 8, group_step: 1 },
    // Overlapping views of one register, in the shape x86 needs. All five name
    // the same storage; they differ only in which bits they see and what a
    // write does to the rest. `eax` zeroing while `al` preserves is not a
    // quirk of this table -- it is what the architecture does, and a class
    // without a policy cannot say both.
    RegisterClass { name: "x86_r64", file: "x86_gpr", lowering_family: "x86_r64", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "x86_r32", file: "x86_gpr", lowering_family: "x86_r32", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "x86_r16", file: "x86_gpr", lowering_family: "x86_r16", file_width: None, zero_index: None, alias: None, view_width: Some(16), view_offset: 0, write_policy: WritePolicy::Preserve, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "x86_r8lo", file: "x86_gpr", lowering_family: "x86_r8lo", file_width: None, zero_index: None, alias: None, view_width: Some(8), view_offset: 0, write_policy: WritePolicy::Preserve, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "x86_r8hi", file: "x86_gpr", lowering_family: "x86_r8hi", file_width: None, zero_index: None, alias: None, view_width: Some(8), view_offset: 8, write_policy: WritePolicy::Preserve, limbs: 1, offset: 0, index_offset: 0, group_step: 1 },
    // A vector register file, placed above the scalar one. The corpora that
    // describe scalable vectors had every operand in `reg` at offset 0 --
    // including the base-address register of a load -- while a vector operand
    // strides by `VL / 64` slots. So `z1` occupied slots 2 and 3 and `x2`
    // occupied slot 2: the same storage, silently. It stayed invisible for as
    // long as no instruction named both files, which contiguous loads and
    // stores do.
    //
    // The scalar file goes first because its size is fixed; putting the vector
    // file first would move the scalars every time VL changed.
    RegisterClass { name: "vreg", file: "vreg", lowering_family: "vreg", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 0, group_step: 1 },
    // SVE's predicate registers. The same file as the vector registers and the
    // same stride -- a predicate lane here is an element-wide 0 or 1, so a
    // predicate register is exactly as wide as a Z register -- but 32 registers
    // further along, so `p3` and `z3` are not the same storage. They were,
    // until an instruction named both at once.
    RegisterClass { name: "preg", file: "preg", lowering_family: "preg", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 32, group_step: 1 },
    // SME's ZA array, as rows: one register is one SVL-bit row, and the four
    // element-size views step through it by their interleave. All four name
    // the same file, because they are views of one storage -- writing
    // ZA0.S changes ZA0.B, which is the point (S2).
    RegisterClass { name: "za_b", file: "za", lowering_family: "za", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 64, group_step: 1 },
    RegisterClass { name: "za_h", file: "za", lowering_family: "za", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 64, group_step: 2 },
    RegisterClass { name: "za_s", file: "za", lowering_family: "za", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 64, group_step: 4 },
    RegisterClass { name: "za_d", file: "za", lowering_family: "za", file_width: None, zero_index: None, alias: None, view_width: None, view_offset: 0, write_policy: WritePolicy::Zero, limbs: 1, offset: 32, index_offset: 64, group_step: 8 },
    // Views into a 128-bit register held as two limbs. The three cases a limb
    // implementation has to get right are all here on purpose: a view inside a
    // limb, a view exactly filling one, and a view straddling the boundary --
    // the last being the only one that cannot be reached without limbs at all.
    RegisterClass { name: "v128_s0", file: "v128", lowering_family: "v128_s0", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Preserve, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "v128_s1", file: "v128", lowering_family: "v128_s1", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 32, write_policy: WritePolicy::Preserve, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "v128_d1", file: "v128", lowering_family: "v128_d1", file_width: None, zero_index: None, alias: None, view_width: Some(64), view_offset: 64, write_policy: WritePolicy::Preserve, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
    RegisterClass { name: "v128_cross", file: "v128", lowering_family: "v128_cross", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 48, write_policy: WritePolicy::Preserve, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
    // Zeroing, on a register that is more than one limb. "The rest becomes
    // zero" has to mean the rest of the *register*, not the rest of the slot
    // the view happens to land in -- an x86 VEX write of XMM zeroes the upper
    // half of its YMM, which is a whole limb away from the bits written.
    RegisterClass { name: "v128_z0", file: "v128", lowering_family: "v128_z0", file_width: None, zero_index: None, alias: None, view_width: Some(32), view_offset: 0, write_policy: WritePolicy::Zero, limbs: 2, offset: 0, index_offset: 0, group_step: 1 },
];

/// How many slots a flat register file needs to hold every class, when no
/// operand asks for more. A floor rather than the answer: see
/// `register_file_slots`.
///
pub const REGISTER_FILE_SLOTS: u32 = 64;

/// How many slots *this document's* register file needs.
///
/// The constant above was the whole answer while every register occupied one
/// slot and no class was addressed past index 31. A scalable register occupies
/// `VL / 64` of them, so 32 Z registers at VL = 128 need exactly the 64 slots
/// that used to be the ceiling, and at VL = 256 need twice that. A file sized
/// by the old constant would place the top registers on top of nothing, which
/// reads as zero rather than as an error.
pub fn register_file_slots(document: &Document) -> u32 {
    let mut needed = REGISTER_FILE_SLOTS;
    for instruction in &document.instructions {
        for operand in &instruction.operands {
            let Some(class) = register_class(&operand.kind) else {
                continue;
            };
            let stride = if operand.slot_stride > 0 {
                operand.slot_stride
            } else {
                class.limbs.max(1)
            };
            // The widest register a five-bit selector reaches, PLUS how far a
            // lane group reaches past it. An SME tile row lives up to 60 rows
            // past the encoded tile, and a file sized by the selector alone
            // ended inside the tile it was meant to hold.
            needed = needed.max(
                class.offset
                    + (class.index_offset + REGISTER_SELECTOR_LIMIT + operand.lane_register) * stride,
            );
        }
    }
    needed
}

/// How many registers a class is addressed with. Five bits in every encoding
/// described so far.
pub const REGISTER_SELECTOR_LIMIT: u32 = 32;

/// One register file's storage, as *this document* needs it.
///
/// ⚠️ The class table cannot answer this on its own. It knows where a file
/// starts and how a view onto it behaves; it does not know how many registers
/// the file has -- that is the width of the selector the description's
/// encodings use -- nor how many slots one register takes when the file is
/// scalable, which moves with VL and is therefore a property of the operand.
/// Both come from the document, which is why this is a function and not a
/// constant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterFileLayout {
    /// The class that names this storage.
    pub class: &'static str,
    /// Which slot the file starts at.
    pub base: u32,
    /// How many registers of this file's own stride precede this class in it.
    pub index_offset: u32,
    /// Slots per register as the CLASS says: `limbs`, which is what every
    /// consumer indexing by class alone uses.
    pub stride: u32,
    /// Slots per register as this document's OPERANDS say, when they say
    /// anything -- 0 when none does.
    ///
    /// ⚠️ These two differ, on purpose, and a layout that published one number
    /// would be hiding it. A scalable register occupies `VL / 64` slots, and
    /// VL is not a property of the class: `vreg` is one limb in the table and
    /// two slots per register in an SVE document at VL = 128. So the executor
    /// has two paths -- an operand with a view uses its own `slot_base` and
    /// `stride`, one without uses the class's arithmetic -- and the storage a
    /// file needs is sized by the wider of them.
    pub lane_stride: u32,
    /// How many registers the description's encodings can name.
    pub registers: u32,
    /// The architectural width of one register, in bits.
    pub bits: u32,
    /// The first slot past this class's registers.
    pub top: u32,
}

/// Every register file this document stores, derived from its own encodings.
///
/// One row per class actually used. Two classes that are views of one file --
/// AArch64's `X` and `W`, x86's `RAX` through `AH` -- share a `base` and
/// overlap on purpose; two files that are *not* views of each other and
/// overlap anyway are a description that corrupts itself, which
/// `register_file_overlaps` reports and nothing used to ask.
pub fn register_files(document: &Document) -> Vec<RegisterFileLayout> {
    use std::collections::BTreeMap;
    // (class, index_offset) -> (stride, registers). A class may appear with
    // several strides across a document's operands -- a scalable file lane
    // instantiated at two VLs would -- and the widest wins, because storage
    // that fits the narrower one does not fit both.
    let mut seen: BTreeMap<&'static str, (u32, u32)> = BTreeMap::new();
    for instruction in &document.instructions {
        let layout = crate::layout::resolve_layout(document, instruction).ok();
        for operand in &instruction.operands {
            let Some(class) = register_class(&operand.kind) else {
                continue;
            };
            let stride = if operand.slot_stride > 0 {
                operand.slot_stride
            } else {
                class.limbs.max(1)
            };
            // ⚠️ How many registers the SELECTOR reaches, not a constant 32. An
            // operand the word does not encode -- a derived pair, a lane -- has
            // no selector of its own and reaches what the operand it derives
            // from reaches. It fell back to the limit instead, which was 32 by
            // coincidence for every five-bit source -- until SME's lanes of a
            // three-bit governing predicate and a two-bit tile made P and ZA
            // files of 32.
            let selector_of = |name: &str| -> u32 {
                layout
                    .as_ref()
                    .map(|layout| {
                        layout
                            .operand_bindings(name)
                            .iter()
                            .map(|field| field.width)
                            .sum()
                    })
                    .unwrap_or(0)
            };
            let mut selector = selector_of(&operand.name);
            if selector == 0 && !operand.derived_from.is_empty() {
                selector = selector_of(&operand.derived_from);
            }
            let registers = if selector == 0 || selector >= 32 {
                REGISTER_SELECTOR_LIMIT
            } else {
                1u32 << selector
            };
            // ⚠️ The operand's stride only when the operand HAS one. Taking
            // it unconditionally made the layout say `vreg[1]` is slot 34
            // where the lifter says 33, because `class.limbs` is 1 and the
            // lane instantiation's stride is 2 -- both true, of different
            // consumers.
            let lane = if operand.slot_stride > 0 { stride } else { 0 };
            let entry = seen.entry(class.name).or_insert((lane, registers));
            entry.0 = entry.0.max(lane);
            entry.1 = entry.1.max(registers);
        }
    }
    seen.into_iter()
        .map(|(name, (lane_stride, registers))| {
            let class = register_class(name).expect("a class that named itself");
            let isa_bits = document
                .isas
                .first()
                .map(|isa| isa.word_bits)
                .unwrap_or(64);
            let stride = class.limbs.max(1);
            // The file has to hold whichever way of indexing it reaches
            // further, because both are used against one array.
            let widest = stride.max(lane_stride);
            RegisterFileLayout {
                class: class.name,
                base: class.offset,
                index_offset: class.index_offset,
                stride,
                lane_stride,
                registers,
                bits: class.file_width.unwrap_or(isa_bits),
                top: class.offset + (class.index_offset + registers) * widest,
            }
        })
        .collect()
}

/// Two files that share storage without being views of one another.
///
/// ⚠️ This is a real way for a description to be wrong and nothing asked it
/// before: `rv_fpr` sits at slot 32 and a `reg128` operand at slot 0 with two
/// slots per register reaches slot 63, so a document using both would have
/// `f0` and `v16` be the same memory. Views of one file overlap on purpose and
/// are not reported -- they name the same `base` and the same lowering family,
/// which is what "a view of" means here.
pub fn register_file_overlaps(document: &Document) -> Vec<(&'static str, &'static str)> {
    let files = register_files(document);
    let mut found = Vec::new();
    for (i, one) in files.iter().enumerate() {
        for other in files.iter().skip(i + 1) {
            let (a, b) = (register_class(one.class), register_class(other.class));
            let (Some(a), Some(b)) = (a, b) else { continue };
            // Views of one file share slots because that is what a view is.
            if a.file == b.file {
                continue;
            }
            let lo = one.base + one.index_offset * one.stride.max(one.lane_stride);
            let other_lo =
                other.base + other.index_offset * other.stride.max(other.lane_stride);
            if lo < other.top && other_lo < one.top {
                found.push((one.class, other.class));
            }
        }
    }
    found
}

/// The ISA an instruction belongs to, whether or not it names one.
///
/// An instruction may name its ISA, and in a document declaring several it has
/// to. In a document declaring exactly one it need not, and twenty-one corpora
/// do not -- which is how the lift table came to omit `state_width` for all of
/// them. The width of a machine's registers and program counter is not
/// ambiguous there; nothing had asked the question in a way that could answer
/// it, so nothing did.
pub fn instruction_isa<'a>(document: &'a Document, instruction: &Instruction) -> Option<&'a Isa> {
    if !instruction.isa.is_empty() {
        return document.isas.iter().find(|isa| isa.name == instruction.isa);
    }
    match document.isas.as_slice() {
        [only] => Some(only),
        _ => None,
    }
}

/// The class a kind names, or `None` when the kind is not a register at all.
pub fn register_class(kind: &str) -> Option<&'static RegisterClass> {
    REGISTER_CLASSES.iter().find(|class| class.name == kind)
}

/// What an operand does, in the vocabulary the lift/lisp/translation artifacts
/// use. `verbose` switches to the encode artifacts' longer spelling.
///
/// One definition because it was five, and the fifth had to grow an arm the
/// moment an operand could be *encoded without being read*. A scalable
/// instruction carries one register selector and reads elements of it, so the
/// selector is bound by decode and named by no expression. Every copy mapped
/// the unused `(false, false)` to "in", which would have fed a register
/// *number* into the semantics where a value belongs — the failure mode that
/// cost 11256 phantom differential failures the last time an operand was
/// misclassified.
pub fn operand_role(operand: &Operand, verbose: bool) -> &'static str {
    match (operand.input, operand.output) {
        (true, true) => "inout",
        (false, true) => {
            if verbose {
                "output"
            } else {
                "out"
            }
        }
        (true, false) => {
            if verbose {
                "input"
            } else {
                "in"
            }
        }
        // Encoded, read by nothing. A consumer that builds an input list from
        // "every operand that is not an output" must skip this one.
        (false, false) => "enc",
    }
}

/// Whether an operand of this kind names a register rather than a literal.
///
/// One definition, because it had grown to six copies — the translation class
/// normalizer, two emitted Python membership tests, the emitted C and Rust
/// effect binders, and a `startswith("a64_gpr")` patch in one harness. The
/// failure mode is silent and identical every time: an AArch64 operand's kind
/// is its register class, so a `kind == "reg"` test classifies it as an
/// immediate and the *register number* gets used where its value belongs. That
/// cost 11256 phantom differential failures before it was traced back here.
pub fn is_register_kind(kind: &str) -> bool {
    register_class(kind).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operand {
    pub name: String,
    pub kind: String,
    pub width: u32,
    /// Read by the instruction. Plain operands and `:inout` operands are
    /// inputs; `:out` operands are write-only.
    pub input: bool,
    /// Written by the instruction. `:out` and `:inout` operands are outputs.
    pub output: bool,
    /// This operand names an *element* of its register rather than the
    /// register, and `width` is the element's.
    ///
    /// The other way an operand is narrower than its register is a *window* --
    /// `a64_gpr32` is the W view of an X, at a fixed offset with a fixed write
    /// policy. A window is owned by the class and needs no marker, because the
    /// class is the marker. An element is owned by the *instruction*: `z0.b`
    /// and `z0.h` are one register and one class, differing only in what that
    /// instruction calls an element, which is exactly why elements cannot be
    /// classes.
    ///
    /// A lane-instantiated scalable instruction says this by construction, so
    /// only the fixed-width vectors need to say it here: `(fadd v2f32 vn vm)`
    /// names two 32-bit lanes of a 128-bit register.
    pub element: bool,
    /// Optional encoded operand whose register selector this operand derives
    /// from. Used for architectural adjacent-register pairs such as AArch64
    /// CASP, where only the first register of each pair is encoded.
    pub derived_from: String,
    /// Register-index offset applied to `derived_from` after decode.
    pub derived_add: u32,
    /// The register this operand always names, when no bits select it:
    /// `(fixed 16)`. SVE's FFR is the case that asked -- a predicate every
    /// first-fault and non-fault load reads and writes, named by no field.
    /// A fixed operand is as fully encoded as a field-bound one: its number is
    /// known at decode, so lanes may derive from it as they do from a field.
    pub fixed: Option<u32>,
    /// How the assembly's number relates to the encoded field, when they are
    /// not the same number.
    ///
    /// AArch64's fixed-point `SCVTF` encodes `scale` and its assembly prints
    /// `fbits`, which is `64 - scale`. Until this existed the description had
    /// to pick one and be wrong about the other: the corpus printed the
    /// encoded field and called it fbits, contradicting its own semantics
    /// string in the same instruction.
    ///
    /// ⚠️ Only transforms that are their own inverse, or have one as cheap,
    /// belong here. An assembler must be able to go back: text to field, not
    /// only field to text. `AsmTransform` is closed for exactly that reason --
    /// a general expression would need inverting, and an uninvertible one
    /// would publish a disassembler that cannot be assembled back.
    pub asm_transform: AsmTransform,
    /// For a lane operand of an instantiated scalable instruction: where the
    /// element it names sits, as `(register past the encoded one, element
    /// within that register)`.
    ///
    /// This is the element-to-register packing, published rather than modelled.
    /// Modelling it as a *value* would mean representing a whole VL-bit
    /// register, and `Sem::Int` holds a `u128` — so at VL = 512 there is no
    /// value to hold it in, which is the same ceiling that made lane-indexed
    /// instantiation necessary in the first place. Stating the mapping costs
    /// nothing and is what a consumer actually needs: given the encoded
    /// register number, these two say exactly which element this operand is.
    ///
    /// `lane_register` is `lane / (VLEN / elem)` and `lane_element` is
    /// `lane % (VLEN / elem)`, so an operand at LMUL > 1 names a register past
    /// the encoded one — which is precisely what register grouping is.
    pub lane_register: u32,
    pub lane_element: u32,
    /// Which lane this operand *is*. Not always the instruction's own lane: a
    /// reduction is one instruction whose operands span every lane, so the
    /// instruction's `scalable_lane` says nothing about them. Published for the
    /// same reason as everything else here — the alternative is a consumer
    /// reading the index back out of the `__l<n>` suffix.
    pub lane_index: u32,
    /// Whether the two above mean anything, since zero is a real position.
    pub lane_packed: bool,
    /// Where this operand's value sits inside the register it names, when the
    /// register class cannot say.
    ///
    /// A class is a compile-time row: it can hold x86's `AH` because that view
    /// is a property of the architecture. It cannot hold "element 5 of a Z
    /// register", because which bits those are depends on VL and the element
    /// width, both of which are per-document. So the *operand* carries the
    /// view, and the class keeps saying which file and where it starts.
    ///
    /// `slot_stride` is how many 64-bit slots one register of this operand's
    /// file occupies; zero means "one, as the class says". `view_width` zero
    /// means "no override — read the whole register as the class describes it".
    pub slot_stride: u32,
    pub view_offset: u32,
    pub view_width: u32,
    /// The slot this operand's register file starts at. Usually the class's
    /// `offset`; different when the file sits above a scalable one, whose size
    /// moves with VL.
    pub slot_base: u32,
}

/// The predictor that answers AT FETCH on a core whose own predictor needs
/// until decode (docs/ooo_design.md, D3). Fetch goes where this one says;
/// `cycles` later the core's predictor has its answer, and where the two
/// disagree the front end is redirected -- to the target decode reads out of
/// the word when the quick guess was "not taken", back to the fall-through
/// when it was "taken". What the machine predicted, and what a mispredict is,
/// is the core's predictor's alone: this one costs time, not accuracy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickPredictor {
    /// `bimodal`: two-bit counters by pc. A quick predictor keeps no history.
    pub predictor: String,
    pub entries: u32,
    /// Cycles after the fetch at which the core's predictor overrides it.
    pub cycles: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreUnit {
    pub name: String,
    /// How many of this unit the core has. Two adders issue two adds a cycle.
    pub count: u32,
    /// Whether a new operation may start before the last one finishes. An
    /// unpipelined unit is busy for the instruction's whole latency; a
    /// pipelined one for its issue interval.
    ///
    /// ⚠️ A unit declares no LATENCY. The instruction already declares one,
    /// and a second place to write the same number is how a field becomes
    /// free text -- `expected-speedup` is 1.0 on all 338 instructions of one
    /// corpus precisely because nothing ever had to agree with it.
    pub pipelined: bool,
    /// How many lanes one copy of this unit processes per cycle, on a SIMT
    /// core (docs/simt_design.md). Zero -- the default -- is as wide as the
    /// warp. A warp instruction occupies the unit for ceil(warp lanes / unit
    /// lanes) cycles, every lane, active or not: that is how a narrow datapath
    /// under a wide warp costs time, and why the warp width alone is not the
    /// machine's throughput.
    pub lanes: u32,
    /// The operand that carries how many ELEMENTS an instruction on this unit
    /// works on (docs/vector_units_design.md, VU2): `(length vl)`. An
    /// instruction naming such an operand takes lanes for that many elements,
    /// not for its whole register -- two beats' worth of register is one
    /// beat's worth of work when half of it is tail. Empty: every instruction
    /// takes its register's width.
    pub length: String,
    /// Other units of this core whose instructions may issue on this one's
    /// idle lanes (docs/vector_units_design.md, VU3): `(accepts alu)`. An
    /// instruction tries its own unit first and borrows a lane here only when
    /// that has no copy free; a vector instruction's lanes are its own for as
    /// long as it holds them.
    pub accepts: Vec<String>,
    /// What this unit costs when SEVERAL CORES share it
    /// (docs/vector_units_design.md, VU4): `(transport N)`, the cycles a
    /// result takes to come back from a unit that is not the core's own, and
    /// `(switch N)`, the cycles it takes to change which core it is serving --
    /// SME's streaming-mode entry. Both zero on a unit nobody shares, where
    /// neither is read: which machines share is the host's to say.
    pub transport: u32,
    pub switch: u32,
    /// Operations this unit holds in flight at once, each for its latency,
    /// on a SIMT core. ⚠️ A cap, not an initiation interval: two in flight
    /// for 14 cycles averages one every 7, but admits two back to back and
    /// then none -- what Vortex's FPU tag queue does (FPU_QUEUE_SIZE 2), and
    /// what the interval this first was could not reproduce (10.47 cycles an
    /// op where SimX measures 6.98). Zero is no cap.
    pub interval: u32,
    /// How many instructions may wait for THIS unit (S2): `(queue N)`. An
    /// instruction bound for a unit whose queue is full does not enter the
    /// window, and nothing behind it does either. Zero is no queue of its
    /// own: the core's one issue queue is the only limit.
    pub queue: u32,
    /// Whether an operation in this unit is ABORTED when it is squashed
    /// (docs/ooo_design.md, W4): `(abort true)`. A unit that is not pipelined
    /// is held for an instruction's whole latency, and by default it stays
    /// held when the instruction turns out to be on a wrong path -- the model
    /// stops waiting for the result, the unit does not stop computing it. A
    /// unit that aborts is free the cycle after the squash. Whether a divider
    /// can be flushed is a property of the divider, which is why this is the
    /// unit's to say and not the core's.
    pub abort: bool,
}

/// What makes a `(kind simt)` core a machine rather than a label
/// (docs/simt_design.md): warps of lanes executing in lockstep under a
/// thread mask, a reconvergence stack per warp, and a scheduler choosing
/// among warps every cycle.
///
/// ⚠️ The SPLIT of the ISA and the reconvergence of the machine are two
/// halves of one operation, written in two places on purpose. What each LANE
/// computes -- its predicate, the token it receives -- is the instruction's
/// `behavior`, executed through the generated executor like any other; what
/// the WARP does with those values -- push, pop, narrow the mask, wait at a
/// barrier -- is `warp_control`, bound here by mnemonic. An ISA cannot
/// describe a warp, and a core should not re-describe a predicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSimt {
    /// Warps resident on the core.
    pub warps: u32,
    /// Lanes per warp: the thread mask's width. ⚠️ The knob this form exists
    /// for. At most 64, because a mask is one 64-bit word.
    pub lanes: u32,
    /// Which ready warp issues: `gto` (greedy-then-oldest: the warp that
    /// issued last keeps issuing until it stalls) or `rr` (round robin).
    pub scheduler: String,
    /// Reconvergence-stack entries per warp. A SPLIT that would push past
    /// this traps: the machine has no stack left, and silently dropping an
    /// entry would run the wrong lanes after the JOIN.
    pub stack: u32,
    /// The bytes one coalesced memory access covers. Lane addresses falling
    /// in one line of this size are one request.
    pub line: u32,
    /// The ISAs this core decodes, in the order a word is tried: the SIMT
    /// extension first, then the base it extends. Empty is `implements`.
    pub isas: Vec<String>,
    /// The data cache in front of memory: bytes, ways, and the latencies of a
    /// hit and a miss in cycles. Zero bytes is no cache, every line a miss.
    pub cache: CoreSimtCache,
    /// Warp-level roles bound to mnemonics: `tmc`, `wspawn`, `split`, `join`,
    /// `pred`, `bar`, `wsync`. (docs/simt_design.md lists what each does with
    /// the state its instructions' behaviors write.)
    pub warp_control: Vec<(String, Vec<String>)>,
    /// A read of a per-lane machine register the host owns (thread id, warp
    /// id, CTA coordinates): the instruction, its destination operand, and
    /// the index as a sum of operands times weights.
    pub sysread: Option<CoreSimtSysread>,
    /// State slots the machine does not scoreboard. ⚠️ For accumulated,
    /// sticky state -- AArch64's FPSR, which every FP operation reads and
    /// ORs into -- a real core does not serialize on: scoreboarding it would
    /// make every FP instruction wait out the previous one's latency. Named,
    /// never inferred, so the choice is visible in the description.
    pub untracked: Vec<String>,
    /// Vector mode: a warp the host starts in it runs ONE thread whose vector
    /// registers span the lanes -- lane `e` holds element-slice `e` of every
    /// register of the lane classes. Instructions of `isa` execute in every
    /// lane, reading the thread's scalar registers; every other instruction
    /// executes once. The same lanes, units and cache as the SIMT warps.
    pub vector: Option<CoreSimtVector>,
    /// Implicit divergence: the warp needs no SPLIT/JOIN. When its lanes
    /// disagree on the next pc it splits into PATHS itself, runs one at a
    /// time, and merges two whenever their pcs meet. Which path runs is the
    /// policy -- a heuristic for where threads reconverge, which a compiler
    /// would have known exactly.
    pub implicit: Option<CoreSimtImplicit>,
    /// Out-of-order issue: the reorder buffer's entries per warp (0: in
    /// order), and whether control flow is predicted (`perfect`) or waited
    /// out (`none`). An instruction is dispatched in order and starts when
    /// its sources and a unit are ready, not when the warp reaches it; it
    /// retires in order. Divergence is never predicted. The third field is
    /// whether a write under a partial mask waits for the register's previous
    /// writer (it merges into the old value); `false` is the bound a renamer
    /// with no merge cost would reach. The fourth is a `bimodal` predictor's
    /// counters. The fifth is whether memory is an ordering: a load waits for
    /// the youngest older store in its warp's window to any 8 bytes it reads.
    /// The sixth: a divergence predictor, `entries` two-bit counters by pc
    /// saying whether a branch splits the warp. A divergence it foresaw
    /// costs the front end nothing: both paths' pcs are known.
    pub ooo: Option<(u32, String, bool, u32, bool, bool)>,
    /// The exclusive monitor's state slots: address, size, valid. ⚠️ Without
    /// this a store by one thread leaves every other thread's reservation
    /// standing, and a load-exclusive / store-exclusive pair run by a warp's
    /// lanes loses updates: all of them read the old value, and all of their
    /// stores succeed. Declared, a write clears every OTHER lane's
    /// reservation that overlaps it, on every warp.
    pub exclusive: Option<(String, String, String)>,
    /// Per-thread memory the machine interleaves: the region ending at `top`
    /// holds one `bytes`-long slot per thread (warps x lanes), and the
    /// machine lays their `granule`-byte pieces side by side, so the same
    /// offset in adjacent threads is adjacent memory (docs/simt_design.md §3a).
    /// ⚠️ Timing only: a permutation of where the region's bytes live, which
    /// no program can observe -- what a GPU does to "local memory". `None`
    /// keeps every thread's slot contiguous, and then one stack slot across a
    /// 16-lane warp is 16 lines that cannot coalesce.
    pub interleave: Option<(u64, u32, u32)>,
    /// How the interleave groups slots: `0` interleaves all threads' slots
    /// together; `G` interleaves within each group of G consecutive slots
    /// (Vortex: a warp's lanes). `interleave_xor` also XORs each group's
    /// granule index with the group number, so groups' equal offsets land in
    /// different places -- Vortex's `StackInterleave` (sim/simx), and
    /// `VX_lsu_agu.sv` in its RTL, both on by default.
    pub interleave_group: u32,
    pub interleave_xor: bool,
    /// Latency per unit class, replacing what the instructions declare: for a
    /// machine whose pipelines time by class rather than by instruction --
    /// Vortex charges every ALU operation 2 cycles, a multiply included. A
    /// class not named keeps the instructions' own latencies.
    pub class_latency: Vec<(String, u32)>,
    /// Cycles between an instruction's issue and when a dependent instruction
    /// may read its result, beyond its latency: the pipeline stages a real
    /// core puts between them (operand collection, writeback). Zero is the
    /// ideal pipeline every number before this form assumed.
    pub pipeline: u32,
    /// The fewest cycles between two instructions of ONE warp: a front end
    /// that holds a warp until its last instruction has decoded, as Vortex's
    /// does (measured: 9 cycles an instruction for a lone warp, dependent or
    /// not). Zero is one a cycle.
    pub issue_interval: u32,
    /// Latency by mnemonic prefix, over the class's: for a machine whose
    /// pipelines time operations within a class differently -- Vortex's FPU
    /// charges a compare or select 4 cycles and an FMA 14. Longest prefix wins.
    pub mnemonic_latency: Vec<(String, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CoreSimtCache {
    pub bytes: u32,
    pub ways: u32,
    pub hit: u32,
    pub miss: u32,
    /// Cycles memory takes to deliver one line: its bandwidth. Zero is
    /// unbounded. ⚠️ Without it every miss overlaps every other for free,
    /// and a wide warp's coalesced loads cost one latency however many lines
    /// they are -- a memory system no machine has.
    pub fill: u32,
    /// Misses outstanding at once. Zero is unbounded.
    pub mshrs: u32,
    /// Banks the cache serves lines from in parallel, by line address. Zero
    /// or one: one line a cycle, which serializes a warp's uncoalesced access
    /// that a banked cache -- Vortex's has one bank per lane -- serves at once.
    pub banks: u32,
    /// A second level: bytes (0: none), ways, and the cycles from an L1 miss
    /// to its data on a hit there. An L2 miss costs `miss`, as with no L2.
    pub l2_bytes: u32,
    pub l2_ways: u32,
    pub l2_hit: u32,
    /// A stride prefetcher at L1, per (warp, pc): once one load has moved by
    /// the same number of lines twice, the next `prefetch_degree` requests'
    /// lines are fetched ahead. Zero: none. Its fetches take miss slots and
    /// memory bandwidth like any miss.
    pub prefetch_degree: u32,
    pub prefetch_entries: u32,
    /// `prefetch-next-line 1`: instead of strides by (warp, pc), on every
    /// demand miss fetch the next `prefetch_degree` lines. ⚠️ A per-warp
    /// stride never trains on a GPU-style kernel: warps take thread blocks in
    /// the order they finish, so one warp's loads jump by varying amounts.
    pub prefetch_next_line: u32,
    /// `prefetch-best-offset 1`: Michaud's best-offset prefetcher (HPCA
    /// 2016). One global offset D, learnt by testing candidate offsets
    /// against a table of `prefetch_entries` recently filled lines: offset d
    /// scores at an access to line X when X - d was filled before now, so an
    /// offset scores only if prefetching with it would have been in time. On
    /// every demand miss and first use of a prefetched line, fetch X + D
    /// (`prefetch_degree` lines from there). Global, so warps taking blocks in
    /// any order do not confuse it.
    pub prefetch_best_offset: u32,
    /// Whether a line on its way from memory is a line that is there. Not
    /// (`track-fills 1`): an access to it waits for the fill. ⚠️ Off is the
    /// model every result before M14 used, in which a second access to a line
    /// in flight hit at once -- optimistic, and fatal to a prefetcher, whose
    /// lines are all in flight.
    pub track_fills: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSimtImplicit {
    /// `minpc`: the lowest pc. `minsp-pc`: the deepest stack, then the lowest
    /// pc (SIMT-X, DITVA). `maxdepth-pc`: the deepest CALL, counted from the
    /// call and return instructions, then the lowest pc -- for an ISA whose
    /// calls do not move the stack pointer.
    pub policy: String,
    /// The stack pointer's state slot, and the per-thread stack's size (a
    /// power of two: depth is the pointer's distance below a multiple of it).
    pub sp: Option<(String, u32)>,
    pub calls: Vec<String>,
    pub returns: Vec<String>,
    /// Reconvergence hints: instructions that mark where threads meet. A path
    /// whose next instruction is one runs after every path that is not at
    /// one, whatever the policy says; among paths at hints, the policy
    /// decides. The instruction itself does nothing.
    pub yields: Vec<String>,
    /// Forward progress: a path that has issued this many instructions in a
    /// row while another path of its warp waits is set aside, and waits
    /// behind every path that was not (oldest set-aside first). 0: never --
    /// the policy alone decides, and a path spinning on a flag that a parked
    /// path would set can hold the warp for ever.
    pub progress: u32,
    /// Spin-loop hints (A64's YIELD, WFE): executing one sets the running
    /// path aside, as (progress N) does when its count runs out -- it runs
    /// after every path that was not set aside, oldest first. Unlike a
    /// reconvergence hint, which only loses to paths not at a hint: two
    /// spinners both at hints are back to the policy, which can prefer the
    /// same one for ever.
    pub relax: Vec<String>,
    /// A64's events, `(events (wait WFE) (send SEV) (local SEVL))`. Each lane
    /// has an event register. A lane executing a `wait` instruction with its
    /// register clear SLEEPS: its path is not run, and a warp whose paths
    /// all sleep issues nothing, until a `send` (every lane of every warp:
    /// sleepers wake, the rest have their register set). With it set, the
    /// wait clears it and goes on. `local` sets the executing lanes' own.
    /// Without this, the wait instructions are whatever else the core makes
    /// of them -- a spin-loop hint at most -- and a waiting thread spins.
    pub wait: Vec<String>,
    pub send: Vec<String>,
    pub send_local: Vec<String>,
    /// `(path-issue smt)`: a warp's paths issue as SMT threads share a core.
    /// Each path has its own front end -- a path waiting on its branch does
    /// not hold up another that is ready, and a switch costs no fetch -- and
    /// registers are renamed per lane, so two paths writing the same
    /// register do not wait for each other. They still share the warp's
    /// window, units and issue width. An out-of-order core only. Default
    /// (`one`): one path at a time, as the policy picks.
    pub smt: bool,
    /// `(path-issue smt N)`: at most N paths of a warp may wait on their
    /// branches at once -- N front ends. Past that a stalled path holds the
    /// warp as it would with one. 0: as many as there are paths.
    pub smt_fronts: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSimtVector {
    /// The ISA whose instructions are per-lane halves of a vector operation.
    pub isa: String,
    /// Register classes a lane holds its own slice of (the vector file).
    pub lane_classes: Vec<String>,
    /// State a lane holds its own slice of (predicates).
    pub lane_state: Vec<String>,
    /// Vector instructions whose sources are lane 0's: a broadcast.
    pub broadcast: Vec<String>,
    /// A predicate test: the state slot that receives the flags, and the
    /// vector instructions that set them. Each lane leaves its active
    /// elements in `simt_arg` and whether its last element is active in
    /// `simt_arg2`; the thread's flags are first-active (bit 3), none-active
    /// (bit 2) and last-not-active (bit 1) over all lanes -- one result from
    /// every lane, which no lane can compute.
    pub flags: Option<(String, Vec<String>)>,
    /// Vector instructions that read OTHER lanes' slices (a permute). While
    /// one executes, the machine presents every lane's value of each
    /// lane-class source, and of each lane-state slot, as memory at
    /// `XLANE_BASE` (see `docs/simt_design.md` §3c): the whole register,
    /// lane 0 first. The behavior loads what it needs; those loads are not
    /// memory accesses, and the instruction is not a load.
    pub crosslane: Vec<String>,
    /// Vector instructions that are a reduction: each lane leaves its part
    /// in `simt_arg`, and the machine writes the sum (modulo 2^64) to the
    /// instruction's lane-class destination in lane 0, clearing the rest.
    pub sum: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreSimtSysread {
    pub mnemonic: String,
    pub dst: String,
    pub index: Vec<(String, u32)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Core {
    pub name: String,
    pub kind: String,
    pub threads: u32,
    pub implements: String,
    /// How many instructions may begin in one cycle. 0 means undeclared, and
    /// an undeclared width is one -- which is what every core did before a
    /// core could say otherwise.
    pub issue_width: u32,
    /// The functional units this core has, by the names its instructions use.
    /// ⚠️ MACHINE state, not the ISA's. What an instruction means is the
    /// same on a core with one adder and on a core with four; how long a
    /// program takes is not, and that difference is the whole reason this
    /// form exists separately from `definstruction`.
    pub units: Vec<CoreUnit>,
    /// Where this core's latencies and unit assignments differ from its
    /// instructions' own. `None` is a core that says nothing, and is every
    /// core that existed before a core could: the instructions' numbers.
    /// Read through [`Core::latency_of`] and [`Core::unit_of`], never here.
    pub timing: Option<crate::timing::CoreTiming>,
    /// How long this core's cycle is, in the hardware cost model's gate
    /// delays (`docs/hardware_design.md` §5). 0 is a core that does not say.
    /// With it, every instruction that has a netlist has a least number of
    /// cycles, and a core that gives it fewer is refused.
    pub cycle_gates: u32,
    /// What a taken branch costs this core, in cycles: the front end fetched
    /// the fall-through and has to start again somewhere else.
    ///
    /// ⚠️ This is the cost of NOT PREDICTING. A machine with no predictor
    /// pays it on every taken branch, which is what an in-order core without
    /// one does. Zero -- the default -- is a machine whose front end never
    /// stalls, which is what every core modelled here did before it could
    /// say otherwise.
    pub branch_penalty: u32,
    /// How this core guesses where a branch goes. `none` -- the default --
    /// guesses "not taken" every time, which is what a machine with no
    /// predictor does and exactly what the model did before predictors
    /// existed here. `bimodal` keeps two-bit counters indexed by address.
    pub predictor: String,
    /// How many counters `bimodal` keeps. ⚠️ Finite on purpose: two branches
    /// that land on one counter interfere, and whether that matters is the
    /// question a predictor study asks.
    pub predictor_entries: u32,
    /// The reorder buffer, in entries. ⚠️ NON-ZERO MEANS OUT OF ORDER. A core
    /// with no window is the in-order machine this model started as, and its
    /// code path is untouched -- which is what keeps every description
    /// written before this from acquiring a pipeline it never claimed.
    pub rob: u32,
    /// How many dispatched instructions may be waiting to issue at once.
    pub issue_queue: u32,
    /// How many may RETIRE in a cycle. Commit is in order however wide it is.
    pub commit_width: u32,
    /// How many micro-ops may ENTER the window in a cycle
    /// (docs/scheduler_design.md, S1): `(window ... (dispatch-width N))`.
    /// Zero is the issue width, which is what dispatch was held to before a
    /// core could say otherwise.
    pub dispatch_width: u32,
    /// The scheduler's wakeup-and-select loop, in cycles (S3): `(window ...
    /// (schedule N))`. A dependent issues no sooner than N cycles after its
    /// producer issued, however short the producer is. Zero or one is a
    /// scheduler that issues dependents back to back.
    pub schedule: u32,
    /// Which of the instructions ready for a unit the scheduler picks
    /// (docs/scheduler_design.md, S8): `(window ... (select position))`
    /// picks by where each sits in the issue queue -- the lowest slot, which
    /// an instruction took when it entered and a younger one may hold below
    /// an older. Empty, or `oldest`, is by age.
    pub select: String,
    /// What the machine does at rename instead of executing
    /// (docs/rename_design.md, ME1): `(window ... (eliminate moves))`. A
    /// register move -- told from the instruction's value, not named -- takes
    /// an entry in the window and nothing else: no issue-queue slot, no
    /// unit, no register of its own, and what reads its result waits for
    /// what the move read. Empty is a machine that executes its moves.
    pub eliminate: String,
    /// The stores this core has retired and not yet written
    /// (docs/memory_model_design.md, WM1): `(store-buffer (entries 16) (drain
    /// any))`. A store that commits waits here; this core's own loads read
    /// it, and no other core sees it until it drains. Zero is a core whose
    /// stores are memory's the moment they retire.
    pub store_buffer: u32,
    /// How the buffer drains: empty or `order`, oldest first; `any`, each
    /// store when its own line is ready, never past an older one to the same
    /// bytes -- which only a relaxed memory model allows.
    pub store_drain: String,
    /// What this core does with a load another core's store overtakes
    /// (docs/memory_model_design.md, WM2): empty or `order`, the load is
    /// squashed and reads again, so loads see memory in program order; `any`,
    /// it keeps what it read -- unless an older load of the same bytes had
    /// not yet read, or something that orders memory stands before it --
    /// which only a relaxed memory model allows.
    pub load_order: String,
    /// How many results may be given a register in a cycle
    /// (docs/scheduler_design.md, S6): `(window ... (rename-width N))`. An
    /// instruction that writes nothing -- a store, a branch -- takes none of
    /// it. Zero is no limit of its own.
    pub rename_width: u32,
    /// Queues several units share (S5): `(queues (NAME (size N) (units
    /// alu br)) ...)`. An instruction bound for any unit of a queue that is
    /// full does not enter the window.
    pub queues: Vec<(String, u32, Vec<String>)>,
    /// Whether the value predictor follows a STRIDE (S7): `(value-prediction
    /// (kind stride) ...)` predicts the last value plus the last difference,
    /// once that difference has repeated. Otherwise the last value.
    pub value_stride: bool,
    /// A predictor of what a LOAD will read (docs/scheduler_design.md, S4):
    /// `(value-prediction (entries N) (confidence K))`, as `(entries,
    /// confidence)`. A load whose instruction has read the same value K times
    /// running is predicted to read it again: what depends on it does not
    /// wait for it, and if it reads something else everything after it is
    /// fetched again.
    pub value_prediction: Option<(u32, u32)>,
    /// What a result costs to reach another unit (S3): `(bypass (FROM TO N)
    /// ...)`. An instruction on unit TO reading what an instruction on unit
    /// FROM made waits N cycles more than the producer's latency.
    pub bypass: Vec<(String, String, u32)>,
    /// Which implementation is meant to time this core. Empty is AXIS's own
    /// pipeline; a name is an external model, open or not.
    ///
    /// ⚠️ Naming one is a REQUIREMENT, not a hint. A description that asks
    /// for a model the host does not have must be refused rather than fall
    /// back to the built-in pipeline, because falling back produces a
    /// plausible number for a machine nobody asked about.
    pub model: String,
    /// Where this core's numbers came from: `declared` (a designer typed
    /// them), `measured` (put back to hardware and checked), `modelled`
    /// (produced by another model).
    ///
    /// ⚠️ Carried, never inferred. A closed model's cycle count and a count
    /// measured against silicon are different KINDS of number, and a result
    /// that does not say which is free text with a decimal point.
    pub provenance: String,
    /// Parameters AXIS transports and does not interpret, for a model whose
    /// knobs AXIS has never heard of.
    ///
    /// ⚠️ A vendor's microarchitecture is mostly policy, and policy is not
    /// declarable. What AXIS can honestly do is carry the settings intact and
    /// refuse to pretend it understood them.
    pub vendor: Vec<(String, String)>,
    /// The memory this core runs against, by the name a `defmemory` gives it.
    /// ⚠️ Empty for a core that names none, and then the simulator models no
    /// cache until a host configures one -- which is what every machine did
    /// before a core could say.
    pub memory: String,
    /// Personalities composed on this core (P3). Empty = the single-ISA
    /// `implements` form (sugar for one implicit personality).
    pub personalities: Vec<String>,
    pub features: Vec<String>,
    /// How loads and stores are ordered against each other, for a core that
    /// says. `None` is a machine whose memory ordering is not modelled -- a
    /// load waits on registers only -- which is what every core did before
    /// this form, and what keeps them from acquiring a constraint they never
    /// declared. (docs/ooo_design.md, O1)
    pub lsq: Option<CoreLsq>,
    /// Physical registers BEYOND the architectural file, per register class
    /// (docs/ooo_design.md, O2). A class not named renames without limit,
    /// which is what every core did before this form.
    pub rename: Vec<(String, u32)>,
    /// How many outcomes of global history `gshare` folds into its index
    /// (docs/ooo_design.md, O3). Zero for a predictor that keeps none.
    pub predictor_history: u32,
    /// Every other number `(branch ...)` gives its predictor, in order:
    /// TAGE's `tables`, `min-history` and `tag-bits`, or whatever an external
    /// predictor reads (O8). Carried to the predictor as `(key, value)` pairs
    /// rather than a field each, so a predictor AXIS has never heard of takes
    /// its parameters the same way a built-in one does.
    pub predictor_params: Vec<(String, u32)>,
    /// A QUICK predictor the core's own overrides at decode
    /// (docs/ooo_design.md, D3): `(overrides (predictor bimodal) (entries N)
    /// (cycles C))` inside `(branch ...)`. `None` is a core whose one
    /// predictor answers at fetch, which is what every core did before this.
    pub overrides: Option<QuickPredictor>,
    /// The fetch pipeline, for a core that declares one (O6-O7). `None` is a
    /// machine whose instructions reach dispatch the moment they are stepped
    /// and whose mispredict costs the flat `branch_penalty` -- what every
    /// core did before this form.
    pub front_end: Option<CoreFrontEnd>,
    /// Issue ports, each naming the units it feeds (O10). Empty is a core
    /// whose units are their own ports -- what every core was before this
    /// form. A port starts one instruction a cycle, so two units behind one
    /// port cannot both start in the same cycle however many copies each has.
    pub ports: Vec<(String, Vec<String>)>,
    /// How this core is timed (E1). Empty is TRACE-driven: the functional
    /// side runs the path that retires and the pipeline replays it. `execute`
    /// is EXECUTION-driven: the front end fetches the predicted path,
    /// instructions execute when they issue -- through the generated executor,
    /// on values older in-flight instructions produced -- branches resolve
    /// when they execute, wrong-path work occupies the machine until it is
    /// squashed, and commit steps the golden functional model and checks
    /// every result against it.
    pub engine: String,
    /// How a port of a described memory system is charged (U3,
    /// docs/unified_engine_design.md). Empty or `untimed` is what every core
    /// did before: each access adds what it costs beyond a first-level hit, as
    /// if it were the only one in flight. `timed`, on an execution-driven
    /// core, asks the memory system WHEN the access completes -- MSHRs, fills
    /// in flight, DRAM banks and bus, timed prefetching -- so its loads meet
    /// the same contention the system's other ports (SIMT cores among them)
    /// create.
    pub memory_timing: String,
    /// The translation lookaside buffers this core has (docs/tlb_design.md).
    /// `None` is a machine whose translation is free, which is what every
    /// core was before a core could say.
    pub tlb: Option<CoreTlb>,
    /// The exclusive monitor's state slots -- address, size, valid -- for a
    /// core that shares memory with others (U4c). ⚠️ A store-exclusive
    /// succeeds on its own monitor, and nothing in an ISA's semantics says
    /// another core's store clears it: that is the memory system's job. With
    /// this, a store committed by one core clears every other core's monitor
    /// over the bytes it wrote; without it, two contexts both "won" an
    /// LDXR/STXR add and one update was lost. The SIMT clause names the same
    /// three for its lanes.
    pub exclusive: Option<(String, String, String)>,
    /// Events (U4c): the instructions that wait for one, send one to every
    /// core, and set this core's own -- `(events (wait WFE) (send SEV)
    /// (local SEVL))`. Each machine has an event register. A wait that
    /// commits with it set clears it and goes on; with it clear the machine
    /// SLEEPS -- what was fetched after it is squashed, and nothing more is
    /// fetched -- until another machine's send commits. Under OS threads
    /// every wait is a spin loop, and a spinner that sleeps executes nothing:
    /// on a fusing core that is the difference between waiting and taking
    /// the issue slots of the thread being waited for (M17).
    pub events: Option<(String, String, String)>,
    /// The warp machine, for a `(kind simt)` core that declares one. `None`
    /// is every core before this form, SIMT-labelled ones included: those stay
    /// labels, timed by nothing.
    pub simt: Option<CoreSimt>,
}

/// How instructions reach dispatch: how many are fetched a cycle, how many
/// cycles they take to get there, and how a taken branch finds its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreFrontEnd {
    /// Instructions fetched per cycle. A branch predicted taken ends the
    /// group it is in: the next instruction comes from somewhere else.
    pub fetch_width: u32,
    /// Cycles from fetch to dispatch. A mispredict's refill is this deep.
    pub depth: u32,
    /// Instructions fetched and not yet dispatched, at most. Zero is
    /// `fetch_width x (depth + 1)`: the stages themselves, and no more.
    pub buffer: u32,
    /// Branch target buffer entries. Zero is a perfect one: every taken
    /// branch's target is known at fetch.
    pub btb: u32,
    /// Cycles a predicted-taken branch whose target the BTB does not hold
    /// costs before fetch resumes at the target decode found.
    pub btb_penalty: u32,
    /// Return-address stack entries (O9). Zero is none: a return's target
    /// comes from the BTB like any indirect jump's. A call pushes the address
    /// after it; a return pops. Calls and returns are DERIVED -- a jump that
    /// links into the ABI's link register, and an indirect jump through it
    /// that does not link -- so no instruction is marked by hand.
    pub ras: u32,
    /// The instruction cache fetch reads through, by the name a `defmemory`
    /// of kind `cache` gives it (O11). Empty is a fetch that never misses.
    pub icache: String,
    /// Whether the front end fetches down the PREDICTED path between a
    /// mispredict and its resolution (O11). Those lines are touched in the
    /// instruction cache -- warming it or polluting it -- and never executed.
    pub wrong_path_fetch: bool,
    /// Whether the wrong path is EXECUTED (O12): at a mispredict the
    /// functional side forks, runs down the predicted path with its writes
    /// buffered and its traps swallowed, and is restored exactly; the timing
    /// model then lets as much of that run as the machine could have reached
    /// before resolution touch the caches -- its own control flow for the
    /// instruction cache, its loads and stores for the data cache.
    pub wrong_path_execute: bool,
    /// A cache of DECODED micro-ops (docs/micro_ops_design.md, U2):
    /// `(op-cache (entries N) (ways W) (window B) (width K) (depth D))`.
    /// Code the machine has decoded before is delivered from here instead of
    /// being fetched and decoded again: no instruction-cache lookup, `width`
    /// micro-ops a cycle instead of `fetch-width` instructions, and `depth`
    /// stages to dispatch instead of the front end's.
    pub op_cache: Option<OpCache>,
    /// A buffer a small loop is replayed from (U2): `(loop-buffer (ops N)
    /// (width K) (depth D))`. A backward branch taken twice running over a
    /// body of at most N micro-ops turns it on; from then the body comes out
    /// of the buffer, `width` micro-ops a cycle, and the loop's own branch
    /// does not end a fetch group.
    pub loop_buffer: Option<LoopBuffer>,
    /// A DECOUPLED front end (docs/front_end_design.md, FQ1):
    /// `(target-queue N)`. The predictor runs ahead of fetch, naming a line
    /// of code a cycle and at most N beyond the one fetch is reading, and a
    /// line is asked of the instruction cache when it is named rather than
    /// when fetch arrives at it. Zero is a front end that predicts where
    /// fetch is and no further.
    pub target_queue: u32,
}

/// `(op-cache ...)`: `entries` windows of `window` bytes of code, `ways` to a
/// set, delivering `width` micro-ops a cycle `depth` stages from dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpCache {
    pub entries: u32,
    pub ways: u32,
    pub window: u32,
    pub width: u32,
    pub depth: u32,
}

/// `(loop-buffer ...)`: a loop of at most `ops` micro-ops, delivered `width`
/// a cycle `depth` stages from dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopBuffer {
    pub ops: u32,
    pub width: u32,
    pub depth: u32,
}

/// One translation buffer: how many pages it holds and in how many ways.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlbLevel {
    /// Zero is a level the core does not have.
    pub entries: u32,
    /// Zero is fully associative: any page in any entry.
    pub ways: u32,
    /// What a hit HERE costs an access that missed the level above. Only the
    /// second level has one: a first-level hit is in the instruction's own
    /// latency, as a first-level cache hit is.
    pub latency: u32,
}

/// A core's TLBs (`(tlb ...)` on `defcore`).
///
/// ⚠️ TIMING, not translation. The machine's addresses stay what the program
/// computes -- no page table is read and nothing faults -- so what this
/// models is how many distinct pages a program touches against how many the
/// machine remembers, and what forgetting one costs. A machine property, as
/// a BTB is: written on the core, not on a `defmemory`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CoreTlb {
    /// Looked up by every load and store.
    pub data: TlbLevel,
    /// Looked up by fetch, once per page it enters.
    pub fetch: TlbLevel,
    /// One second level behind both, where a first-level miss looks before
    /// the page table is walked.
    pub second: TlbLevel,
    /// Zero is 4096.
    pub page_bytes: u32,
    /// What a miss in every level costs: the walk.
    pub walk_cycles: u32,
    /// How many walks may be in progress at once (docs/tlb_design.md, TLB2):
    /// `(walkers N)`. A miss that finds them all busy waits for one. Zero is
    /// no limit, which is what a walk was.
    pub walkers: u32,
    /// A walk that READS THE PAGE TABLE (TLB2): `(walk (levels L) (cycles C)
    /// (table ADDR))`, in place of `(walk-cycles N)`. Each level is one entry
    /// read through the data cache -- C cycles, and whatever the cache
    /// charges for a line it does not hold -- from a table of tables laid
    /// out from ADDR. Zero levels is the flat cost.
    pub walk_levels: u32,
    pub walk_level_cycles: u32,
    pub walk_table: u64,
    /// A cache of the page table's upper levels (TLB2): `(walk-cache
    /// (entries N))`. A walk starts below the deepest level it holds.
    pub walk_cache: u32,
    /// A region mapped with LARGE pages (TLB2): `(huge (bytes B) (from A)
    /// (to Z))`. An address in it is on a page of B bytes, which one entry
    /// remembers all of, and its walk is a level shorter.
    pub huge_bytes: u64,
    pub huge_from: u64,
    pub huge_to: u64,
}

/// A load/store queue: how many of each may be in flight, when a load may
/// pass an older store, and whether a store hands its value to a load that
/// reads what it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreLsq {
    /// Loads in flight at once. Zero is as many as the window holds.
    pub loads: u32,
    /// Stores in flight at once, retirement included. Zero is the window.
    pub stores: u32,
    /// `conservative`: a load waits until every older store has computed its
    /// address. `perfect`: a load waits only for older stores it overlaps --
    /// an oracle, affordable here because the trace knows every address.
    /// `speculative`: a load never waits for an unknown address, and is
    /// squashed and replayed when an older store's address turns out to
    /// overlap it. `store-sets`: speculative, and a load that has collided
    /// with a store before waits for that store next time (O5).
    pub disambiguation: String,
    /// Cycles a memory-order violation costs before the squashed load and
    /// everything younger may issue again. Read by the speculating policies
    /// only.
    pub replay: u32,
    /// Entries in the store-set table, indexed by instruction address. Read by
    /// `store-sets` only, and required by it.
    pub store_sets: u32,
    /// True: a load reads an in-flight older store's value once the store
    /// has executed. False: it waits until the store has retired.
    pub forwarding: bool,
}

/// An execution discipline: how a personality binds lanes/threads to
/// sequencing, e.g. `lockstep(lanes=8)`. Structured metadata in stage P1
/// (flows to the capsule/topology manifests); it does not change semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discipline {
    pub kind: String,
    pub params: Vec<(String, u32)>,
}

impl Default for Discipline {
    fn default() -> Self {
        Self {
            kind: "independent".to_string(),
            params: vec![("threads".to_string(), 1)],
        }
    }
}

/// One slot of an issue packet: a syllable position of a fixed width holding
/// any instruction whose unit class the slot accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSlot {
    pub name: String,
    /// Syllable width in bits, at most 32 — a packet is a container of
    /// ordinary instruction words, not one wide word
    /// (`docs/vliw_spatial_design.md` §3).
    pub width: u32,
    /// Functional-unit classes this slot can hold. Non-empty.
    pub units: Vec<String>,
}

/// An issue packet: the row of slots a machine issues together (stage B1).
///
/// The packet decides *when* its syllables issue and never *what* they mean —
/// a syllable in a packet and the same instruction issued alone have one
/// semantics, the instruction's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub name: String,
    /// The mode value this packet issues in. Empty means every mode, which is
    /// what a machine with one issue mechanism means.
    pub mode: String,
    /// The ISA whose instructions fill these slots. Empty binds the packet to
    /// the document's single instruction space.
    pub isa: String,
    pub slots: Vec<PacketSlot>,
    /// Syllable order in memory: `little` puts slot 0 at the lowest address.
    pub order: String,
    /// How a packet ends: `fixed` (always every slot) or `stop_bit` (a bit in
    /// each syllable says whether the group continues).
    pub end: String,
    /// Bit index of the stop bit within a syllable, when `end` is `stop_bit`.
    pub stop_bit: u32,
    /// `interlocked` (the machine stalls) or `exposed` (the schedule is
    /// responsible). Stage B1 implements only `interlocked`.
    pub hazards: String,
    /// `at_most_one` or `unrestricted` control transfers per packet.
    pub branches: String,
    pub description: String,
}

impl Default for Packet {
    fn default() -> Self {
        Self {
            name: String::new(),
            isa: String::new(),
            mode: String::new(),
            slots: Vec::new(),
            order: "little".to_string(),
            end: "fixed".to_string(),
            stop_bit: 0,
            hazards: "interlocked".to_string(),
            branches: "at_most_one".to_string(),
            description: String::new(),
        }
    }
}

/// A link between two PEs, with the cycles a value spends on it.
///
/// Both the neighbour patterns and the explicit form resolve to these: a
/// consumer of the manifest reads one edge list and never has to know which
/// spelling produced an edge, which is what lets an irregular topology and a
/// mesh be checked by the same code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricLink {
    pub from_row: u32,
    pub from_col: u32,
    pub to_row: u32,
    pub to_col: u32,
    /// Cycles a value spends in flight. At least 1 -- a zero-latency link is a
    /// wire, and a wire between two PEs that both compute in one cycle is a
    /// combinational path the schedule cannot account for.
    pub latency: u32,
    /// The neighbour direction this came from (`north`), or empty for an
    /// explicitly declared edge.
    pub direction: String,
}

/// A memory port: a row of the grid that reaches a named memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FabricPort {
    pub row: u32,
    pub memory: String,
}

/// A spatial fabric: a grid of processing elements and the links between them
/// (`docs/vliw_spatial_design.md` §4.3, stage G1).
///
/// The PEs reuse the *same* unit classes a packet's slots declare, so an
/// operation legal on a VLIW `alu` slot is legal on an `alu` PE with no second
/// declaration and no second semantics. That is the whole reason a fabric is
/// described here rather than in its own language: one instruction set, two
/// ways of issuing it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Fabric {
    pub name: String,
    pub rows: u32,
    pub cols: u32,
    /// Functional-unit classes a PE holds unless its row says otherwise.
    /// Non-empty once every row is accounted for.
    pub units: Vec<String>,
    /// Registers each PE has for values it holds between cycles.
    pub regs: u32,
    /// Constant registers each PE has.
    pub consts: u32,
    pub links: Vec<FabricLink>,
    pub ports: Vec<FabricPort>,
    /// The largest initiation interval a mapping onto this fabric may declare.
    pub ii_max: u32,
    /// How many configurations each PE holds.
    ///
    /// A PE does one thing per configuration, so a mapping that places two
    /// operations on one PE -- at different residues, which the modulo rule
    /// permits -- is asking it to hold two. One is the classic spatial CGRA,
    /// where a PE is configured once and does that forever; more is a
    /// multi-context fabric, where a context selector picks between stored
    /// configurations.
    ///
    /// This exists because the model without it is not honest: `ii` up to
    /// `ii-max` residues per PE were placeable with nothing saying the
    /// hardware could hold them, so a mapping needing sixteen configurations
    /// on a single-context machine validated.
    pub contexts: u32,
    /// The mode value this fabric runs in. Empty means every mode.
    ///
    /// A fabric sharing a row with a packet must name a *different* mode than
    /// that packet: they are one set of functional units, so a machine that
    /// could issue both at once would be using each unit twice. The exclusivity
    /// is the architecture, and stating it in prose is not the same as making
    /// a description that violates it impossible.
    pub mode: String,
    /// The row whose PEs *are* a packet's slots, and that packet's name.
    ///
    /// This is the defining relation of an ADRES-like machine: the VLIW's
    /// functional units are the array's first row, not a copy of it. That is
    /// why the two modes are exclusive -- they are one set of units -- and why
    /// values cross between them through the register file rather than being
    /// transferred. Declaring it makes the correspondence checkable: as many
    /// columns as slots, and each PE holding what its slot holds.
    pub vliw_row: Option<(u32, String)>,
    /// Rows whose PEs differ from the fabric-wide default.
    ///
    /// A uniform grid is the simple case and stays the default, but the
    /// canonical CGRA is not uniform: an ADRES-style machine's first row *is*
    /// its VLIW's functional units -- multiply, memory, branch -- and the rows
    /// below hold plain ALUs. Without this the unit check on a placement
    /// cannot fail, because every PE holds every unit the fabric names.
    pub pe_rows: Vec<FabricPeClass>,
    pub description: String,
}

/// What the PEs of one band of rows hold, where that differs from the default.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FabricPeClass {
    /// Inclusive row range this describes.
    pub first_row: u32,
    pub last_row: u32,
    pub units: Vec<String>,
    pub regs: u32,
    pub consts: u32,
}

impl Fabric {
    /// Every PE position, row-major.
    pub fn positions(&self) -> Vec<(u32, u32)> {
        (0..self.rows)
            .flat_map(|row| (0..self.cols).map(move |col| (row, col)))
            .collect()
    }

    /// The class describing this row, if one overrides the default.
    pub fn pe_class(&self, row: u32) -> Option<&FabricPeClass> {
        self.pe_rows
            .iter()
            .find(|class| row >= class.first_row && row <= class.last_row)
    }

    /// The unit classes one PE holds.
    ///
    /// On a shared row the packet's slots *are* the PEs, column by column, so
    /// the slot decides -- which is what lets a VLIW row be heterogeneous
    /// across its columns while ordinary rows are uniform. `packet` is the
    /// shared packet when there is one; a caller without it gets the row's
    /// answer, which is correct for every unshared row.
    pub fn units_at_pe<'a>(
        &'a self,
        row: u32,
        col: u32,
        packet: Option<&'a Packet>,
    ) -> &'a [String] {
        if let (Some((shared, _)), Some(packet)) = (&self.vliw_row, packet) {
            if *shared == row {
                if let Some(slot) = packet.slots.get(col as usize) {
                    return &slot.units;
                }
            }
        }
        self.units_at(row)
    }

    /// The unit classes a PE in this row holds, ignoring any shared packet.
    pub fn units_at(&self, row: u32) -> &[String] {
        match self.pe_class(row) {
            Some(class) => &class.units,
            None => &self.units,
        }
    }

    /// The registers a PE in this row holds between cycles.
    pub fn regs_at(&self, row: u32) -> u32 {
        self.pe_class(row).map_or(self.regs, |class| class.regs)
    }

    /// The constant registers a PE in this row holds.
    pub fn consts_at(&self, row: u32) -> u32 {
        self.pe_class(row).map_or(self.consts, |class| class.consts)
    }

    /// Every unit class held anywhere on the grid.
    pub fn all_units(&self) -> Vec<String> {
        let mut out = self.units.clone();
        for class in &self.pe_rows {
            for unit in &class.units {
                if !out.iter().any(|held| held == unit) {
                    out.push(unit.clone());
                }
            }
        }
        out
    }

    /// Whether this position is on the grid.
    pub fn holds(&self, row: u32, col: u32) -> bool {
        row < self.rows && col < self.cols
    }
}

/// One operation of a mapping: an instruction placed on a PE at a cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingOp {
    /// The name the routes and the scalar order refer to it by.
    pub id: String,
    pub mnemonic: String,
    pub row: u32,
    pub col: u32,
    /// The absolute cycle it issues at. Resource legality is this modulo the
    /// initiation interval, which is what makes the schedule a *modulo* one.
    pub cycle: u32,
}

/// A value moving from one operation to another along a path of links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingRoute {
    pub from: String,
    pub to: String,
    /// Which input operand of the consumer this value arrives at.
    ///
    /// Required rather than inferred. An operation with two inputs and one
    /// route has one routed operand and one free one, and which is which
    /// decides what the mapping computes -- `(sub rs1 rs2)` is not
    /// `(sub rs2 rs1)`. A default that picked the first unrouted operand would
    /// be right for the commutative cases and silently wrong for the rest.
    pub operand: String,
    /// The PEs the value passes through, starting at the producer's and ending
    /// at the consumer's.
    ///
    /// Positions only, where `docs/vliw_spatial_design.md` §4.4 sketched
    /// positions interleaved with direction names. A direction between two
    /// given PEs is a fact about the fabric's links, so writing it here too
    /// would be a second derivation of the topology that could disagree with
    /// the first -- the exact failure `fabric_manifest.json` publishes an
    /// expanded edge list to avoid.
    pub via: Vec<(u32, u32)>,
    pub cycle: u32,
    /// How many iterations back the value comes from. `0` is the same
    /// iteration; `1` means iteration *k* feeds iteration *k+1*.
    ///
    /// A software-pipelined loop is exactly this: a value produced late in one
    /// iteration is consumed early in the next, and without a way to say so
    /// the only expressible mappings are the ones whose dataflow fits inside
    /// one iteration. It also makes the latency check *exact* rather than
    /// modular -- `producer + latency + flight == consumer + distance * ii` is
    /// an equation on absolute cycles, where the same statement modulo `ii`
    /// cannot tell one iteration's value from another's.
    pub distance: u32,
    /// The elastic channel this value crosses, or empty for a statically timed
    /// route. Naming one exempts the route from modulo legality: the two
    /// timing models are different, and bolting a latency window onto residue
    /// arithmetic would produce a check that means neither thing.
    pub channel: String,
}

/// An elastic channel: a value in flight whose arrival time is not a static
/// function of the schedule (stage G4b).
///
/// Everything B3, G2 and G3 prove rests on `vliw_spatial_design.md` §10's rule
/// that a value's arrival time *is* such a function. A handshake breaks it, so
/// a route that names a channel carries a different obligation instead: the
/// result does not depend on the timing.
///
/// The protocol is a name and not a model (`elastic_seams_design.md` §4). AXIS
/// does not describe handshake wires, and no gate here can say a handshake is
/// implemented correctly -- that is the consumer's rung, the same boundary
/// `personality_design.md` §9 draws.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Channel {
    pub name: String,
    /// `ready-valid` or `credit`: an identifier a consumer matches on.
    pub protocol: String,
    /// The arrival window in cycles, inclusive. `latency_min` is what a
    /// consumer may assume; `latency_max` is what it must tolerate.
    pub latency_min: u32,
    pub latency_max: u32,
    /// Buffered tokens. Zero is a pure wire, and a cycle of pure wires is a
    /// deadlock -- which is decidable from this number without executing
    /// anything.
    pub capacity: u32,
    /// `preserving` (tokens leave as they entered) or `unordered`.
    pub order: String,
    /// The value the buffer starts holding, for a channel that closes a cycle.
    ///
    /// A ring with no initial token cannot start: every operation on it waits
    /// for a value that only the ring produces. Real hardware primes the
    /// buffer, and a description that cannot say so describes a machine that
    /// never runs -- which is what the first elastic corpus here did, and what
    /// made its latency-insensitivity gate pass by comparing two empty
    /// results.
    pub initial: u32,
    pub description: String,
}

/// A mapping: a CGRA's program, as a placement and a routing (stage G2).
///
/// AXIS checks a mapping; it does not compute one. Placement and routing are a
/// compiler's search problem, and the boundary is the one
/// `personality_design.md` §9 draws: AXIS judges the spec, the consumer judges
/// the silicon, and neither self-certifies the other's claim.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mapping {
    pub name: String,
    pub fabric: String,
    /// Where each operand no route feeds gets its value.
    ///
    /// Without these a mapping is a dataflow with inputs from nowhere: the G3
    /// gate hands every unrouted operand an anonymous random value, which
    /// proves the placement and the timing and says nothing about what the
    /// kernel reads out of the machine. A live-in is what makes it a *state*
    /// transformation -- and two operands bound to one register must see one
    /// value, which anonymous inputs could never require.
    pub live_in: Vec<MappingLiveIn>,
    /// Which architectural register each result is left in.
    pub live_out: Vec<MappingLiveOut>,
    /// Initiation interval: the schedule repeats every `ii` cycles.
    pub ii: u32,
    pub ops: Vec<MappingOp>,
    pub routes: Vec<MappingRoute>,
    /// The same operations in scalar order -- what this mapping is claimed to
    /// compute, and the subject of the G3 gate.
    pub equivalent_to: Vec<String>,
    pub description: String,
}

/// Where a value entering the fabric comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingSource {
    /// An architectural register, by index in the operand's own file.
    Register(u32),
    /// A constant held in the PE's constant register. A fabric whose PEs have
    /// none cannot supply one, which is why `consts` is checked against this.
    Constant(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingLiveIn {
    pub op: String,
    pub operand: String,
    pub source: MappingSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingLiveOut {
    pub op: String,
    pub register: u32,
}

impl Mapping {
    pub fn op(&self, id: &str) -> Option<&MappingOp> {
        self.ops.iter().find(|op| op.id == id)
    }
}

/// One spelling of a unit class, for every place that has to decide whether two
/// of them are the same one.
///
/// A slot declares `(units ALU)` and an instruction `(unit alu)`; comparing
/// them raw makes those two different classes, and the instruction would be
/// rejected as held by no slot. Case and hyphens are how the rest of this
/// language already normalises an enumerated value.
pub fn canonical_unit(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

impl Packet {
    /// Slot indices that can hold an instruction of unit class `unit`.
    pub fn slots_for_unit(&self, unit: &str) -> Vec<usize> {
        let unit = canonical_unit(unit);
        self.slots
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.units.iter().any(|candidate| canonical_unit(candidate) == unit))
            .map(|(index, _)| index)
            .collect()
    }

    /// Total container width in bits when every slot is present.
    pub fn container_bits(&self) -> u32 {
        self.slots.iter().map(|slot| slot.width).sum()
    }
}

/// A mode selector (P2): a WARL-encoded CSR field whose value gates decode
/// legality. `values` names the modes; instructions carry the modes they are
/// legal in. At most one mode block per document in v1.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mode {
    pub name: String,
    pub csr: u32,
    pub field_hi: u32,
    pub field_lo: u32,
    pub values: Vec<(String, u32)>,
    pub default: String,
    pub description: String,
}

/// A named, parameterised behavior over an iteration space
/// (`docs/tensor_design.md`, T8).
///
/// ⚠️ Not new semantics, and the premise test is why. After T8b a whole
/// matmul is writable as one flat behavior -- four stores, each a contraction
/// over loads -- and the behavior-level `iterate` already spells its space.
/// What a kernel adds is the three things that flat form cannot carry: a NAME
/// several launches share, PARAMETERS they bind to their own operands, and a
/// SPACE a consumer can read without re-deriving it from four copies of the
/// same store that differ only in literals.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Kernel {
    pub name: String,
    /// Bound positionally to the launching instruction's operands.
    pub params: Vec<String>,
    /// The output space, outermost first: one `(index extent)` per dimension.
    pub space: Vec<(String, u32)>,
    /// The body statements as written, re-emitted verbatim so the canonical
    /// form keeps the kernel rather than its expansion.
    pub body: Vec<String>,
    pub description: String,
}

/// A launch descriptor: a block of memory the host fills in and an engine
/// reads (`docs/accelerator_design.md`, H1b).
///
/// AHA's loader already knew a descriptor as a schema NAME and a byte count.
/// This is what the name stood for: where each field is, what the engine
/// refuses and what it writes when it does, and where it says so.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Descriptor {
    pub name: String,
    pub bytes: u32,
    pub fields: Vec<DescriptorField>,
    /// In order: the first failing check decides the status.
    pub checks: Vec<DescriptorCheck>,
    /// The field holding the address the status is written to. Empty when
    /// the status is RETURNED instead -- `(status returned <type>)` -- into
    /// the launching instruction's output, which is how an engine that
    /// reports through a register rather than through memory says so.
    pub status_field: String,
    pub status_width: u32,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DescriptorField {
    pub name: String,
    /// Bytes from the descriptor's base.
    pub offset: u32,
    pub width: u32,
    pub signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DescriptorCheck {
    /// The comparison as written, over field names and literals.
    pub condition: String,
    /// What the engine writes to the status when this check fails. Nonzero:
    /// zero is success.
    pub status: u64,
}

/// An MMIO device: a window of registers, each an access whose effect is an
/// instruction of the device's own ISA (`docs/accelerator_design.md`, H3).
///
/// A register with a side effect -- a stream that advances a pointer, a kick
/// that computes, a result port that pops -- is not a location a load or a
/// store can describe. Its effect is a behavior, and AXIS already has a way to
/// state a behavior and hold it to every backend: an instruction. So a device
/// is its register map, and each register names the handler that runs when
/// the host touches it, over a memory that is the device's own state.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Device {
    pub name: String,
    /// The ISA the handlers belong to.
    pub isa: String,
    /// Bytes of address space the device answers.
    pub window: u32,
    pub registers: Vec<DeviceRegister>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeviceRegister {
    /// Bytes from the window's base.
    pub offset: u32,
    /// `read` or `write`.
    pub access: String,
    /// The instruction that runs on this access.
    pub handler: String,
}

/// One field of a memory-resident configuration block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConfigField {
    pub name: String,
    /// Byte offset inside the block.
    pub at: u32,
    /// Width in bytes.
    pub width: u32,
    /// The values the architecture allows. A configuration a machine cannot be
    /// put into is not a configuration, and enumerating them is what makes the
    /// instantiation below checkable rather than asserted.
    pub values: Vec<u64>,
}

/// A configuration a machine reads from **memory** rather than from a CSR
/// (`docs/tensor_design.md`, T5). AMX's `LDTILECFG` reads 64 bytes: a palette
/// byte, a start row, eight column counts and eight row counts.
///
/// ⚠️ This declares no semantics. An instruction that reads such a block and
/// writes the state it configures is describable without it -- measured, by
/// writing one: sixteen `setstate`s from sixteen loads validate and emit
/// through every backend. What was missing is that **nothing said those state
/// slots were a configuration**, and nothing published where in the block each
/// one lives, so a runtime that must build the block had to read byte offsets
/// out of an effect expression.
///
/// So this is a second statement of a layout the semantics already imply, and
/// its value is that the two are required to agree. `configures` on the
/// instruction is what ties them, and validation refuses a description whose
/// loads and whose declaration disagree about an offset.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub name: String,
    /// Size of the block in bytes.
    pub bytes: u32,
    pub fields: Vec<ConfigField>,
    /// The point this document is elaborated at: one value per field. A
    /// description is static, so the configuration it describes is one
    /// configuration -- named, rather than left to be inferred from the shapes
    /// elsewhere in the document.
    pub instantiate: Vec<(String, u64)>,
    pub description: String,
}

/// A personality: an ISA view bound to an execution discipline and a portable
/// state capsule (see `docs/personality_design.md`, stage P1). The mode
/// binding arrives in stage P2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalitySeam {
    /// The exported unit's name at the seam. An import binds to it by this
    /// name, which is why both sides carry one.
    pub name: String,
    /// Export only: the unit class this personality lends across the seam.
    pub unit: String,
    /// Import only: the personality whose export this binds to.
    pub from: String,
    /// This side's channel. An export's is what it promises; an import's is
    /// what it can tolerate, and the two are checked against each other rather
    /// than assumed to match.
    pub channel: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Personality {
    pub name: String,
    /// The mode value that activates this personality (P3). Empty = unbound
    /// (a checkpoint-ABI personality with no mode selector).
    pub mode: String,
    pub implements: String,
    pub discipline: Discipline,
    /// Portable state: register-group names from the implemented ISA
    /// (`x[32]`, `pc`). Empty means the ISA's full declared register surface.
    pub capsule: Vec<String>,
    /// Functional units this personality lends across a boundary, each over a
    /// channel (P5 / G4b.3). An exported unit is an elastic channel at a
    /// personality boundary, which is why this and the fabric's handshakes are
    /// one mechanism rather than two.
    pub exports: Vec<PersonalitySeam>,
    /// Units it borrows, and from whom.
    pub imports: Vec<PersonalitySeam>,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratorPort {
    pub name: String,
    pub direction: String,
    pub kind: String,
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceleratorResult {
    /// The output port this expression defines.
    pub port: String,
    /// The rendered semantic expression, typed against that port's width.
    pub expr: String,
}

/// An accelerator's declared behaviour.
///
/// ⚠️ `formal_semantics` holds the FIRST result only, and is kept because every
/// single-result consumer reads it. `formal_results` is the whole truth: before
/// it existed, `defaccelerator` typed its `formal` expression against the first
/// output port and dropped every other one **silently** -- an engine declaring
/// `(q output ...)` and `(r output ...)` emitted a one-result SMT function and
/// so carried a proof obligation covering half of what it produced. An output
/// port with no expression is now an error rather than a silence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accelerator {
    pub name: String,
    pub family: String,
    pub subtype: String,
    pub descriptor_version: u32,
    pub descriptor_schema: String,
    pub descriptor_bytes: u32,
    /// The declared descriptor `descriptor_schema` names, when the document
    /// declares one (`docs/accelerator_design.md`, H1c). Carried here so every
    /// artifact that describes the accelerator can publish the layout AHA's
    /// loader otherwise knew only as a name and a byte count.
    pub descriptor: Option<Descriptor>,
    pub launch_abi: String,
    pub completion: String,
    pub mmio_base: u32,
    pub mmio_size: u32,
    pub target: String,
    pub coupling: String,
    pub region_id: u32,
    pub manifest_version: u32,
    pub profile: String,
    pub backend_kind: String,
    pub exec_shape: String,
    pub simd_lanes: u32,
    pub element_width_bits: u32,
    pub fallback_policy: String,
    /// When the engine's writes become visible to the host
    /// (`docs/tensor_design.md`, T9): `immediate`, `atomic-at-completion` or
    /// `progressive`. Empty means undeclared, which is what every accelerator
    /// meant before this existed.
    ///
    /// ⚠️ Declared rather than derived, and cross-checked rather than trusted.
    /// A tightly coupled engine completes inside the instruction and has
    /// nothing to poll; a queue-descriptor one does not and must say how the
    /// host learns it is done. Those are the same fact stated twice --
    /// `coupling` and this -- and validation requires them to agree.
    pub visibility: String,
    /// Whether the launch orders the host's prior stores against the engine's
    /// reads: `prior-stores` or `none`.
    pub launch_fence: String,
    /// What the host may observe in the output region while the engine runs:
    /// `unchanged` or `undefined`. Only meaningful when the writes are not
    /// immediate, and refused otherwise.
    pub in_flight: String,
    /// Hardware contexts this engine retains at once (M1). 0 = not declared,
    /// which is the single-context machine AXIS described before this existed.
    /// The word is `deffabric`'s too, and deliberately: both answer "how many
    /// of these does the hardware hold", and what differs -- a configuration
    /// cannot starve, a context can -- is what the rest of the form says.
    pub contexts: u32,
    /// Bits an issue carries to name its context. Declared rather than derived,
    /// so the relation between it and `contexts` is a thing to check instead of
    /// a thing to assume.
    pub context_id_bits: u32,
    /// Issues held at once: the one being serviced plus what is prefetched
    /// behind it. A depth of one hides no latency, which is the engine's whole
    /// purpose, so it is a bound rather than a preference.
    pub issue_queue_depth: u32,
    /// What every issue retains. Must name `context_id`: an issue that cannot
    /// say which context it came from cannot have its result returned to one.
    pub identity: Vec<String>,
    /// The issue policy, a name a consumer matches on (M2). AXIS never models
    /// the arbiter; what the name decides here is whether a service bound
    /// exists to publish at all.
    pub scheduling: String,
    /// Where a context can lose the engine. Without a rotation point a
    /// work-conserving policy is still work-conserving and still unbounded,
    /// which is why this is a second field and not a flavour of the first.
    pub preemption: String,
    /// Cycles between successive services of the resident unit. The time base
    /// the service bound is denominated in; 0 = not stated, and then only the
    /// bound in grants is published.
    pub service_interval_cycles: u32,
    /// The signals that decide whether a context may be granted. Named, not
    /// modelled, for the same reason a channel's protocol is.
    pub eligibility: Vec<String>,
    pub ports: Vec<AcceleratorPort>,
    pub semantics: String,
    pub formal_semantics: String,
    /// One entry per output port, in port order. Empty when the engine states
    /// no `formal` at all.
    pub formal_results: Vec<AcceleratorResult>,
    pub latency_cycles: u32,
    pub throughput_per_cycle: String,
    pub resources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Memory {
    pub name: String,
    pub kind: String,
    /// 64 bits, since a DRAM is a memory too and most are past 4 GiB.
    pub size_bytes: u64,
    pub ports: u32,
    /// What a miss costs, for a cache; what an access costs, for a scratchpad.
    pub latency_cycles: u32,
    pub width_bits: u32,
    pub banks: u32,
    /// Bytes per line, and how many lines share a set. ⚠️ Both zero means
    /// this memory is not a cache -- a scratchpad has neither, and a
    /// description that gave one a line size would be describing a structure
    /// it does not have.
    pub line_bytes: u32,
    pub ways: u32,
    pub attributes: Vec<String>,
    /// How a cache behaves and what a DRAM is (`memsys::MemoryPolicy`).
    pub policy: crate::memsys::MemoryPolicy,
}

impl Default for Memory {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: "sram".to_string(),
            size_bytes: 0,
            ports: 1,
            latency_cycles: 1,
            width_bits: 32,
            banks: 1,
            line_bytes: 0,
            ways: 0,
            attributes: Vec::new(),
            policy: crate::memsys::MemoryPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tile {
    pub name: String,
    pub cores: Vec<String>,
    pub accelerators: Vec<String>,
    pub memories: Vec<String>,
    pub interconnect: String,
}

#[cfg(test)]
mod register_class_tests {
    use super::*;

    /// The table's invariants, which the emitters assume rather than check.
    ///
    /// Each is a way a class could be written that no backend serves correctly
    /// and none would report: a view wider than a machine word cannot be held
    /// in the ≤ 64-bit values every emitted expression computes with, and a
    /// view reaching past its register's limbs would read a *neighbouring*
    /// register's storage — silently, and only for some indices.
    #[test]
    fn views_fit_the_registers_they_describe() {
        for class in REGISTER_CLASSES {
            let limbs = class.limbs.max(1);
            let capacity = limbs * 64;
            if let Some(width) = class.view_width {
                assert!(
                    width <= 64,
                    "{}: a {width}-bit view needs limb arithmetic, which no \
                     backend has; see docs/limbs.md §8",
                    class.name
                );
                assert!(
                    class.view_offset + width <= capacity,
                    "{}: view [{}, {}) reaches past the register's {capacity} bits",
                    class.name,
                    class.view_offset,
                    class.view_offset + width
                );
            } else {
                // No view means the whole register, and for more than one limb
                // that is only answerable if the class says how wide the whole
                // register is -- then a read is every limb, concatenated, which
                // is what the graph's `limbs` on a live-in and a live-out
                // already carry. Without a declared width there is nothing to
                // say which limb a read means, and that is the shape this
                // rejects.
                assert!(
                    limbs == 1 || class.file_width == Some(capacity),
                    "{}: a class with no view is either one limb or declares \
                     the width of all {limbs} of them; it says {:?}",
                    class.name,
                    class.file_width
                );
            }
        }
    }

    /// A register file that does not fit the flat array places its top
    /// registers on top of nothing, which reads as zero rather than as an
    /// error. Limbs made this reachable: the same 32 registers now need 64
    /// slots at two limbs each.
    #[test]
    fn every_class_fits_the_flat_file() {
        for class in REGISTER_CLASSES {
            let top = class.offset
                + (class.index_offset + REGISTER_SELECTOR_LIMIT) * class.limbs.max(1);
            // A file placed above a scalable one reaches past the floor by
            // construction -- `register_file_slots` is what sizes those, from
            // the strides a document actually uses. So does a file of
            // multi-limb registers sitting above another file: AArch64's 32
            // vector registers at two limbs each need 64 slots from 32, and
            // `register_file_slots` computes exactly this expression over the
            // classes a document names. The floor is for the one-slot case.
            if class.index_offset > 0 || class.limbs > 1 {
                continue;
            }
            assert!(
                top <= REGISTER_FILE_SLOTS,
                "{}: register {} lands at slot {top}, past the file's {}",
                class.name,
                REGISTER_SELECTOR_LIMIT - 1,
                REGISTER_FILE_SLOTS
            );
        }
    }
}
