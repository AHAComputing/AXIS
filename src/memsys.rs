//! The memory system: what a machine's memories are, how they connect, and
//! which of them keep each other coherent (`docs/memory_system_design.md`).
//!
//! Three forms carry it. `defmemory` already said what one memory *is*; it now
//! also says how a cache behaves (replacement, write policy, allocation,
//! outstanding misses, inclusion, prefetch) and what a DRAM is (a JEDEC
//! standard, its geometry and its timing). `definterconnect` is the fabric
//! between them: a topology, virtual channels, buffers, widths, per-hop cost.
//! `defmemsys` places instances of the memories on that fabric, names the
//! level below each cache, says which node is a coherence home, and maps
//! address ranges to the endpoints behind them.
//!
//! ⚠️ One description, several consumers, and none of them is privileged: the
//! pack's simulator times a machine against it, and AHA's NoC and CHI
//! generators build the memory fabric and the coherent fabric from the same
//! `axis.memsys.v1` manifest. What each needs is therefore stated once here,
//! in the vocabulary of the machine rather than of any one consumer, and each
//! lowering is a function of the manifest alone.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use crate::ast::{Document, Memory};
use crate::lisp::{SExpr, SExprKind, Span};

/// A parse failure, located. `lisp.rs` turns it into its own error type.
pub type Failure = (Span, String);

fn fail<T>(span: Span, message: impl Into<String>) -> Result<T, Failure> {
    Err((span, message.into()))
}

fn items<'a>(form: &'a SExpr, context: &str) -> Result<&'a [SExpr], Failure> {
    match &form.kind {
        SExprKind::List(items) => Ok(items),
        _ => fail(form.span, format!("{context} must be a list")),
    }
}

fn word<'a>(form: Option<&'a SExpr>, span: Span, context: &str) -> Result<&'a str, Failure> {
    match form {
        Some(SExpr { kind: SExprKind::Atom(atom), .. }) => Ok(atom),
        Some(other) => fail(other.span, format!("{context} must be an atom")),
        None => fail(span, format!("missing {context}")),
    }
}

fn value(form: Option<&SExpr>, span: Span, context: &str) -> Result<u64, Failure> {
    let text = word(form, span, context)?;
    let digits = text.replace('_', "");
    let parsed = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        digits.parse::<u64>()
    };
    parsed.map_err(|_| (span, format!("{context} `{text}` is not a number")))
}

/// `(name value)`: the one value of a property.
fn one<'a>(values: &'a [SExpr], span: Span, name: &str) -> Result<&'a SExpr, Failure> {
    if values.len() != 2 {
        return fail(span, format!("`{name}` expects exactly one value"));
    }
    Ok(&values[1])
}

fn u32_of(values: &[SExpr], span: Span, name: &str) -> Result<u32, Failure> {
    let v = value(Some(one(values, span, name)?), span, name)?;
    u32::try_from(v).map_err(|_| (span, format!("`{name}` {v} does not fit 32 bits")))
}

fn atom_of(values: &[SExpr], span: Span, name: &str) -> Result<String, Failure> {
    Ok(word(Some(one(values, span, name)?), span, name)?.to_string())
}

// ---- how a memory behaves ------------------------------------------------------

/// A DRAM's timing, in its own clock cycles except the clock itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DramTiming {
    pub tck_ps: u32,
    pub tcl: u32,
    pub trcd: u32,
    pub trp: u32,
    pub tras: u32,
}

/// What a `(kind dram)` memory is beyond its size.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dram {
    /// The JEDEC standard the part implements, as `ddr5-4800` -- a name a
    /// consumer may resolve to its own profile, and a gate may hold the
    /// declared timing against.
    pub standard: String,
    pub channels: u32,
    /// Bytes a channel's bus carries a half-clock (double data rate); 8 when
    /// undeclared. Read by timed accesses only (U1).
    pub bus_bytes: u32,
    pub ranks: u32,
    pub row_bytes: u32,
    /// `open` keeps a row after an access; `closed` precharges.
    pub page_policy: String,
    pub timing: DramTiming,
}

/// The behavior of a cache, and the geometry of a DRAM. All empty for a
/// memory that is neither -- a scratchpad has no replacement policy, and a
/// round trip that invented one would be describing a structure it lacks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryPolicy {
    /// `lru`, `plru`, `fifo` or `random`.
    pub replacement: String,
    /// `write-back` or `write-through`.
    pub write_policy: String,
    /// `write-allocate` or `no-write-allocate`.
    pub allocate: String,
    /// Outstanding misses the cache can hold; 0 is blocking.
    pub mshrs: u32,
    /// `inclusive`, `exclusive` or `nine` (neither).
    pub inclusion: String,
    /// `next-line` or `stride`; empty is none.
    pub prefetch: String,
    pub prefetch_degree: u32,
    /// Prefetches that may wait for an MSHR when every one is busy; past
    /// that they are dropped. 0: a prefetch never waits. Timed accesses only.
    pub prefetch_queue: u32,
    /// A cache that serves one request a cycle and none while a miss is on
    /// its way, with no write buffer: a dirty line replaced is written behind
    /// before the line that replaces it is asked for, and a store waits for
    /// its line as a load does (docs/blocking_cache_design.md). A core's own
    /// cache, on the execution-driven engine.
    pub blocking: bool,
    pub dram: Option<Dram>,
}

pub const REPLACEMENTS: &[&str] = &["lru", "plru", "fifo", "random"];
pub const WRITE_POLICIES: &[&str] = &["write-back", "write-through"];
pub const ALLOCATIONS: &[&str] = &["write-allocate", "no-write-allocate"];
pub const INCLUSIONS: &[&str] = &["inclusive", "exclusive", "nine"];
pub const PREFETCHERS: &[&str] = &["next-line", "stride", "best-offset"];

/// The prefetcher a cache names that this library has not got (PF1), if any.
///
/// ⚠️ OPEN, but not loose -- the rule a core's predictor follows. A NAMESPACED
/// name (`acme.spp`) is one a host binds with `register_prefetcher`; a bare
/// name that is not built in is a typo, and is refused rather than waited
/// for.
pub fn external_prefetcher(policy: &MemoryPolicy) -> Option<&str> {
    policy.prefetch.split_whitespace().find(|kind| kind.contains('.'))
}

pub const PAGE_POLICIES: &[&str] = &["open", "closed"];

/// One `defmemory` property this module owns, or `None` when it is not one.
pub fn memory_property(memory: &mut Memory, values: &[SExpr], span: Span) -> Option<Result<(), Failure>> {
    let name = match values.first() {
        Some(SExpr { kind: SExprKind::Atom(name), .. }) => name.as_str(),
        _ => return None,
    };
    let policy = &mut memory.policy;
    let result = (|| -> Result<(), Failure> {
        match name {
            "replacement" => policy.replacement = atom_of(values, span, name)?,
            "write-policy" => policy.write_policy = atom_of(values, span, name)?,
            "allocate" => policy.allocate = atom_of(values, span, name)?,
            "mshrs" => policy.mshrs = u32_of(values, span, name)?,
            "inclusion" => policy.inclusion = atom_of(values, span, name)?,
            "prefetch" => {
                // One or more prefetchers, kept as one space-separated string
                // so every consumer that read a name still reads one.
                let mut names = Vec::new();
                for v in &values[1..] {
                    names.push(word(Some(v), span, name)?.to_string());
                }
                if names.is_empty() {
                    return Err((span, format!("`{name}` names a prefetcher")));
                }
                policy.prefetch = names.join(" ");
            }
            "prefetch-degree" => policy.prefetch_degree = u32_of(values, span, name)?,
            "prefetch-queue" => policy.prefetch_queue = u32_of(values, span, name)?,
            "blocking" => {
                policy.blocking = match atom_of(values, span, name)?.as_str() {
                    "true" => true,
                    "false" => false,
                    other => return fail(span, format!("`blocking` is true or false, not `{other}`")),
                }
            }
            "standard" => policy.dram.get_or_insert_with(Dram::default).standard = atom_of(values, span, name)?,
            "channels" => policy.dram.get_or_insert_with(Dram::default).channels = u32_of(values, span, name)?,
            "bus-bytes" => policy.dram.get_or_insert_with(Dram::default).bus_bytes = u32_of(values, span, name)?,
            "ranks" => policy.dram.get_or_insert_with(Dram::default).ranks = u32_of(values, span, name)?,
            "row-bytes" => policy.dram.get_or_insert_with(Dram::default).row_bytes = u32_of(values, span, name)?,
            "page-policy" => {
                policy.dram.get_or_insert_with(Dram::default).page_policy = atom_of(values, span, name)?
            }
            "timing" => {
                let timing = &mut policy.dram.get_or_insert_with(Dram::default).timing;
                for entry in &values[1..] {
                    let pair = items(entry, "timing entry")?;
                    let key = word(pair.first(), entry.span, "timing parameter")?;
                    let n = u32_of(pair, entry.span, key)?;
                    match key {
                        "tck-ps" => timing.tck_ps = n,
                        "tcl" => timing.tcl = n,
                        "trcd" => timing.trcd = n,
                        "trp" => timing.trp = n,
                        "tras" => timing.tras = n,
                        other => return fail(entry.span, format!("unsupported DRAM timing parameter `{other}`")),
                    }
                }
            }
            _ => return Err((span, String::new())),
        }
        Ok(())
    })();
    match result {
        Err((_, message)) if message.is_empty() => None,
        other => Some(other),
    }
}

// ---- the fabric ------------------------------------------------------------------

/// Where a node can sit, and how far apart two places are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Topology {
    Mesh { rows: u32, cols: u32 },
    Torus { rows: u32, cols: u32 },
    Ring { nodes: u32 },
    Crossbar { ports: u32 },
}

impl Topology {
    pub fn kind(&self) -> &'static str {
        match self {
            Topology::Mesh { .. } => "mesh",
            Topology::Torus { .. } => "torus",
            Topology::Ring { .. } => "ring",
            Topology::Crossbar { .. } => "crossbar",
        }
    }

    /// Columns and rows: a ring and a crossbar are one row.
    pub fn grid(&self) -> (u32, u32) {
        match self {
            Topology::Mesh { rows, cols } | Topology::Torus { rows, cols } => (*cols, *rows),
            Topology::Ring { nodes } => (*nodes, 1),
            Topology::Crossbar { ports } => (*ports, 1),
        }
    }

    pub fn places(&self) -> u32 {
        let (cols, rows) = self.grid();
        cols * rows
    }

    /// Router hops between two places. ⚠️ A crossbar is one hop between any
    /// two ports and zero to itself; a ring and a torus take the shorter way
    /// round. Dimension order (X then Y) on a grid, which is also what makes
    /// the mesh's routing deadlock-free, so the count is the route's.
    pub fn hops(&self, a: (u32, u32), b: (u32, u32)) -> u32 {
        let wrap = |d: u32, n: u32| d.min(n - d);
        match self {
            Topology::Mesh { .. } => a.0.abs_diff(b.0) + a.1.abs_diff(b.1),
            Topology::Torus { rows, cols } => {
                wrap(a.0.abs_diff(b.0), *cols) + wrap(a.1.abs_diff(b.1), *rows)
            }
            Topology::Ring { nodes } => wrap(a.0.abs_diff(b.0), *nodes),
            Topology::Crossbar { .. } => u32::from(a != b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interconnect {
    pub name: String,
    pub topology: Topology,
    pub virtual_channels: u32,
    pub buffer_depth: u32,
    pub flit_bits: u32,
    pub address_bits: u32,
    /// What one link traversal costs, and what one router adds.
    pub hop_cycles: u32,
    pub router_cycles: u32,
}

pub fn elaborate_interconnect(form: &SExpr) -> Result<Interconnect, Failure> {
    let list = items(form, "definterconnect")?;
    let name = word(list.get(1), form.span, "definterconnect name")?.to_string();
    let mut topology = None;
    let mut ic = Interconnect {
        name,
        topology: Topology::Crossbar { ports: 0 },
        virtual_channels: 1,
        buffer_depth: 4,
        flit_bits: 64,
        address_bits: 48,
        hop_cycles: 1,
        router_cycles: 1,
    };
    for property in &list[2..] {
        let values = items(property, "definterconnect property")?;
        let key = word(values.first(), property.span, "definterconnect property name")?;
        match key {
            "topology" => {
                let kind = word(values.get(1), property.span, "topology kind")?;
                let mut dims: HashMap<&str, u32> = HashMap::new();
                for dim in &values[2..] {
                    let pair = items(dim, "topology dimension")?;
                    let d = word(pair.first(), dim.span, "topology dimension")?;
                    dims.insert(d, u32_of(pair, dim.span, d)?);
                }
                let need = |d: &str| {
                    dims.get(d).copied().ok_or((property.span, format!("a {kind} topology needs `({d} n)`")))
                };
                topology = Some(match kind {
                    "mesh" => Topology::Mesh { rows: need("rows")?, cols: need("cols")? },
                    "torus" => Topology::Torus { rows: need("rows")?, cols: need("cols")? },
                    "ring" => Topology::Ring { nodes: need("nodes")? },
                    "crossbar" => Topology::Crossbar { ports: need("ports")? },
                    other => return fail(property.span, format!("unsupported topology `{other}`")),
                });
            }
            "virtual-channels" => ic.virtual_channels = u32_of(values, property.span, key)?,
            "buffer-depth" => ic.buffer_depth = u32_of(values, property.span, key)?,
            "flit-bits" => ic.flit_bits = u32_of(values, property.span, key)?,
            "address-bits" => ic.address_bits = u32_of(values, property.span, key)?,
            "hop-cycles" => ic.hop_cycles = u32_of(values, property.span, key)?,
            "router-cycles" => ic.router_cycles = u32_of(values, property.span, key)?,
            other => return fail(property.span, format!("unsupported definterconnect property `{other}`")),
        }
    }
    ic.topology = topology.ok_or((form.span, "definterconnect requires `(topology ...)`".to_string()))?;
    Ok(ic)
}

// ---- the system ------------------------------------------------------------------

pub const PROTOCOLS: &[&str] = &["none", "msi", "mesi", "moesi"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Coherence {
    pub protocol: String,
    /// The coherent link: per-channel credits, transaction and node id widths,
    /// and the depth of a requester's outstanding-transaction table.
    pub credit_depth: u32,
    pub txn_id_bits: u32,
    pub node_id_bits: u32,
    pub table_depth: u32,
    /// Optional protocol mechanisms, by name (`retry`, `qos`, `atomics`...).
    pub features: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemNode {
    pub name: String,
    pub memory: String,
    /// The core this node is private to; empty for a shared one.
    pub core: String,
    pub at: (u32, u32),
    /// The level a miss goes to. Empty for an endpoint.
    pub next: String,
    /// A coherence home: the directory for the addresses mapped to it.
    pub home: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub target: String,
    pub home: String,
    /// Outside coherence on purpose -- a scratchpad, a device window. Said,
    /// not implied by a missing home, so a forgotten home is still an error.
    pub uncached: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemSystem {
    pub name: String,
    /// The period of the cycle every `*-cycles` number in this system counts
    /// -- the cores' clock. A DRAM's timing is in ITS clock, and this is how
    /// the two meet; 0 when undeclared, which a system with a DRAM refuses.
    pub clock_ps: u32,
    pub interconnect: String,
    pub coherence: Coherence,
    pub nodes: Vec<MemNode>,
    pub regions: Vec<Region>,
}

pub fn elaborate_memsys(form: &SExpr) -> Result<MemSystem, Failure> {
    let list = items(form, "defmemsys")?;
    let mut system = MemSystem {
        name: word(list.get(1), form.span, "defmemsys name")?.to_string(),
        coherence: Coherence {
            protocol: "none".into(),
            credit_depth: 4,
            txn_id_bits: 8,
            node_id_bits: 7,
            table_depth: 4,
            features: Vec::new(),
        },
        ..MemSystem::default()
    };
    for property in &list[2..] {
        let values = items(property, "defmemsys property")?;
        let key = word(values.first(), property.span, "defmemsys property name")?;
        match key {
            "interconnect" => system.interconnect = atom_of(values, property.span, key)?,
            "clock-ps" => system.clock_ps = u32_of(values, property.span, key)?,
            "coherence" => {
                for entry in &values[1..] {
                    let pair = items(entry, "coherence property")?;
                    let k = word(pair.first(), entry.span, "coherence property name")?;
                    let c = &mut system.coherence;
                    match k {
                        "protocol" => c.protocol = atom_of(pair, entry.span, k)?,
                        "credit-depth" => c.credit_depth = u32_of(pair, entry.span, k)?,
                        "txn-id-bits" => c.txn_id_bits = u32_of(pair, entry.span, k)?,
                        "node-id-bits" => c.node_id_bits = u32_of(pair, entry.span, k)?,
                        "table-depth" => c.table_depth = u32_of(pair, entry.span, k)?,
                        "features" => {
                            c.features = pair[1..]
                                .iter()
                                .map(|f| word(Some(f), f.span, "feature").map(str::to_string))
                                .collect::<Result<_, _>>()?
                        }
                        other => return fail(entry.span, format!("unsupported coherence property `{other}`")),
                    }
                }
            }
            "nodes" => {
                for entry in &values[1..] {
                    let parts = items(entry, "memsys node")?;
                    let mut node = MemNode {
                        name: word(parts.first(), entry.span, "node name")?.to_string(),
                        ..MemNode::default()
                    };
                    let mut placed = false;
                    for p in &parts[1..] {
                        let pv = items(p, "node property")?;
                        let k = word(pv.first(), p.span, "node property name")?;
                        match k {
                            "memory" => node.memory = atom_of(pv, p.span, k)?,
                            "core" => node.core = atom_of(pv, p.span, k)?,
                            "next" => node.next = atom_of(pv, p.span, k)?,
                            "home" => {
                                if pv.len() != 1 {
                                    return fail(p.span, "`(home)` takes no value");
                                }
                                node.home = true
                            }
                            "at" => {
                                let x = value(pv.get(1), p.span, "at x")?;
                                let y = if pv.len() > 2 { value(pv.get(2), p.span, "at y")? } else { 0 };
                                if pv.len() > 3 {
                                    return fail(p.span, "`(at x y)` takes at most two coordinates");
                                }
                                node.at = (x as u32, y as u32);
                                placed = true;
                            }
                            other => return fail(p.span, format!("unsupported node property `{other}`")),
                        }
                    }
                    if !placed {
                        return fail(entry.span, format!("node `{}` needs `(at x y)`", node.name));
                    }
                    system.nodes.push(node);
                }
            }
            "address-map" => {
                for entry in &values[1..] {
                    let parts = items(entry, "address-map entry")?;
                    if word(parts.first(), entry.span, "address-map entry")? != "region" {
                        return fail(entry.span, "an address-map entry is `(region base size target ...)`");
                    }
                    let mut region = Region {
                        base: value(parts.get(1), entry.span, "region base")?,
                        size: value(parts.get(2), entry.span, "region size")?,
                        target: word(parts.get(3), entry.span, "region target")?.to_string(),
                        home: String::new(),
                        uncached: false,
                    };
                    for p in &parts[4..] {
                        let pv = items(p, "region property")?;
                        match word(pv.first(), p.span, "region property name")? {
                            "home" => region.home = atom_of(pv, p.span, "home")?,
                            "uncached" => {
                                if pv.len() != 1 {
                                    return fail(p.span, "`(uncached)` takes no value");
                                }
                                region.uncached = true
                            }
                            other => return fail(p.span, format!("unsupported region property `{other}`")),
                        }
                    }
                    system.regions.push(region);
                }
            }
            other => return fail(property.span, format!("unsupported defmemsys property `{other}`")),
        }
    }
    Ok(system)
}

// ---- validation ------------------------------------------------------------------

fn one_of(what: &str, value: &str, allowed: &[&str]) -> Result<(), String> {
    if value.is_empty() || allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{what} `{value}` is not one of {}", allowed.join(", ")))
    }
}

/// A memory's policy, checked against what the memory is.
pub fn validate_memory_policy(memory: &Memory) -> Result<(), String> {
    let p = &memory.policy;
    let who = format!("memory `{}`", memory.name);
    one_of(&format!("{who} replacement"), &p.replacement, REPLACEMENTS)?;
    one_of(&format!("{who} write-policy"), &p.write_policy, WRITE_POLICIES)?;
    one_of(&format!("{who} allocate"), &p.allocate, ALLOCATIONS)?;
    one_of(&format!("{who} inclusion"), &p.inclusion, INCLUSIONS)?;
    let mut seen: Vec<&str> = Vec::new();
    let mut external = 0;
    for kind in p.prefetch.split_whitespace() {
        if kind.contains('.') {
            // One: a cache has one place to hang a prefetcher's state, and
            // two policies deciding together is a third policy nobody wrote.
            external += 1;
            if external > 1 {
                return Err(format!("{who} names two prefetchers from outside; a cache binds one"));
            }
        } else {
            one_of(&format!("{who} prefetch"), kind, PREFETCHERS)?;
        }
        if seen.contains(&kind) {
            return Err(format!("{who} names prefetcher `{kind}` twice"));
        }
        seen.push(kind);
    }
    let cache_only = !p.replacement.is_empty() || !p.write_policy.is_empty() || !p.allocate.is_empty()
        || p.mshrs != 0 || !p.inclusion.is_empty() || !p.prefetch.is_empty() || p.blocking;
    if cache_only && memory.line_bytes == 0 {
        return Err(format!("{who} states a cache policy but is not a cache (no line-bytes)"));
    }
    // ⚠️ A blocking cache is ONE structure, and what it is said beside has to be
    // what it is: it holds one miss, writes back, brings a stored line in, and
    // replaces the line used longest ago. Anything else stated with it would
    // be a clause the simulator read and did not act on.
    if p.blocking {
        let clash = if p.mshrs > 1 {
            Some(format!("holds {} misses; a blocking cache holds one", p.mshrs))
        } else if p.write_policy == "write-through" {
            Some("writes through; a blocking cache writes back".to_string())
        } else if p.allocate == "no-write-allocate" {
            Some("does not bring a stored line in; a blocking cache does".to_string())
        } else if !p.replacement.is_empty() && p.replacement != "lru" {
            Some(format!("replaces by `{}`; a blocking cache replaces the line used longest ago", p.replacement))
        } else if !p.prefetch.is_empty() {
            Some("prefetches; a blocking cache asks for nothing it was not asked for".to_string())
        } else {
            None
        };
        if let Some(clash) = clash {
            return Err(format!("{who} is blocking and {clash}"));
        }
    }
    // Tree-PLRU is a binary tree over the ways; any other count has no tree.
    if p.replacement == "plru" && !memory.ways.is_power_of_two() {
        return Err(format!("{who} uses plru over {} ways; a PLRU tree needs a power of two", memory.ways));
    }
    if p.prefetch_degree != 0 && p.prefetch.is_empty() {
        return Err(format!("{who} gives a prefetch degree and no prefetcher"));
    }
    if p.prefetch_queue != 0 && p.prefetch.is_empty() {
        return Err(format!("{who} gives a prefetch queue and no prefetcher"));
    }
    if let Some(dram) = &p.dram {
        if memory.kind != "dram" {
            return Err(format!("{who} gives DRAM geometry but its kind is `{}`", memory.kind));
        }
        one_of(&format!("{who} page-policy"), &dram.page_policy, PAGE_POLICIES)?;
        if dram.row_bytes == 0 || !dram.row_bytes.is_power_of_two() {
            return Err(format!("{who} row-bytes must be a power of two"));
        }
        let t = &dram.timing;
        for (name, v) in [("tck-ps", t.tck_ps), ("tcl", t.tcl), ("trcd", t.trcd), ("trp", t.trp), ("tras", t.tras)] {
            if v == 0 {
                return Err(format!("{who} timing `{name}` must be declared and positive"));
            }
        }
        // ⚠️ A row stays open at least as long as it takes to open and read it.
        if t.tras < t.trcd {
            return Err(format!("{who} tRAS {} is shorter than tRCD {}", t.tras, t.trcd));
        }
    } else if memory.kind == "dram" {
        return Err(format!("{who} is a DRAM and declares no geometry or timing"));
    }
    Ok(())
}

pub fn validate(document: &Document) -> Result<(), String> {
    let memories: HashMap<&str, &Memory> = document.memories.iter().map(|m| (m.name.as_str(), m)).collect();
    for memory in &document.memories {
        validate_memory_policy(memory)?;
    }
    let mut ic_names = HashSet::new();
    for ic in &document.interconnects {
        if !ic_names.insert(ic.name.as_str()) {
            return Err(format!("duplicate interconnect `{}`", ic.name));
        }
        if ic.topology.places() == 0 {
            return Err(format!("interconnect `{}` has no places", ic.name));
        }
        for (what, v) in [("virtual-channels", ic.virtual_channels), ("buffer-depth", ic.buffer_depth),
                          ("flit-bits", ic.flit_bits), ("address-bits", ic.address_bits)] {
            if v == 0 {
                return Err(format!("interconnect `{}` {what} must be positive", ic.name));
            }
        }
        if ic.address_bits > 64 {
            return Err(format!("interconnect `{}` address-bits {} exceeds 64", ic.name, ic.address_bits));
        }
    }
    // ⚠️ A blocking cache keeps time: it is busy until a cycle. So it is a
    // data cache of a core that has cycles when it reaches memory -- the
    // execution-driven engine -- and nothing else may name it.
    for memory in document.memories.iter().filter(|m| m.policy.blocking) {
        let named = |name: &str| name.eq_ignore_ascii_case(&memory.name);
        if let Some(sys) = document.memsystems.iter().find(|s| s.nodes.iter().any(|n| named(&n.memory))) {
            return Err(format!(
                "memory `{}` is blocking and is a node of memory system `{}`; a blocking cache is a core's own",
                memory.name, sys.name
            ));
        }
        for core in &document.cores {
            if core.front_end.as_ref().is_some_and(|f| named(&f.icache)) {
                return Err(format!(
                    "memory `{}` is blocking and core `{}` fetches through it; a blocking cache is a data cache",
                    memory.name, core.name
                ));
            }
            if named(&core.memory) && !core.engine.eq_ignore_ascii_case("execute") {
                return Err(format!(
                    "core `{}` names the blocking cache `{}` and is trace-driven; a cache that is busy until a cycle needs `(engine execute)`",
                    core.name, memory.name
                ));
            }
        }
    }
    let cores: HashSet<&str> = document.cores.iter().map(|c| c.name.as_str()).collect();
    let mut sys_names = HashSet::new();
    for sys in &document.memsystems {
        // ⚠️ A prefetcher from outside is bound by the host of the pack that
        // creates the system, and a SIMT pack offers no call to bind one: a
        // system it created would run with the prefetcher silently absent.
        let outside = sys.nodes.iter().any(|n| {
            memories.get(n.memory.as_str()).is_some_and(|m| external_prefetcher(&m.policy).is_some())
        });
        if outside {
            if let Some(port) = sys.nodes.iter().find(|n| {
                document.cores.iter().any(|c| c.name == n.core && (c.simt.is_some() || c.kind.eq_ignore_ascii_case("simt")))
            }) {
                return Err(format!(
                    "memory system `{}` names a prefetcher from outside and has the SIMT core `{}` as a port; \
                     only a pack-pipeline host can bind one",
                    sys.name, port.core
                ));
            }
        }
        if !sys_names.insert(sys.name.as_str()) {
            return Err(format!("duplicate memsys `{}`", sys.name));
        }
        let who = format!("memsys `{}`", sys.name);
        let ic = document
            .interconnects
            .iter()
            .find(|i| i.name == sys.interconnect)
            .ok_or(format!("{who} names interconnect `{}`, which is not declared", sys.interconnect))?;
        one_of(&format!("{who} protocol"), &sys.coherence.protocol, PROTOCOLS)?;
        let coherent = sys.coherence.protocol != "none";
        let (cols, rows) = ic.topology.grid();
        let mut by_name: HashMap<&str, &MemNode> = HashMap::new();
        let mut places = HashSet::new();
        let mut line = 0u32;
        for node in &sys.nodes {
            if by_name.insert(node.name.as_str(), node).is_some() {
                return Err(format!("{who} declares node `{}` twice", node.name));
            }
            let memory = memories
                .get(node.memory.as_str())
                .ok_or(format!("{who} node `{}` names memory `{}`, which is not declared", node.name, node.memory))?;
            if node.at.0 >= cols || node.at.1 >= rows {
                return Err(format!("{who} node `{}` at ({}, {}) is outside the {} {}x{}",
                                   node.name, node.at.0, node.at.1, ic.topology.kind(), cols, rows));
            }
            // ⚠️ One node per router: a place is where an address map points,
            // and two nodes at one place would make the fabric's address
            // decode ambiguous about which of them a request is for.
            if !places.insert(node.at) {
                return Err(format!("{who} places two nodes at ({}, {})", node.at.0, node.at.1));
            }
            if !node.core.is_empty() && !cores.is_empty() && !cores.contains(node.core.as_str()) {
                return Err(format!("{who} node `{}` is private to core `{}`, which is not declared", node.name, node.core));
            }
            let is_cache = memory.line_bytes != 0;
            if is_cache {
                if node.next.is_empty() {
                    return Err(format!("{who} cache node `{}` names no next level", node.name));
                }
                // One line size throughout: a coherence unit is a line, and
                // two sizes would make one line two units at once.
                if line == 0 {
                    line = memory.line_bytes;
                } else if memory.line_bytes != line {
                    return Err(format!("{who} mixes line sizes ({} and {} bytes)", line, memory.line_bytes));
                }
            } else if !node.next.is_empty() {
                return Err(format!("{who} endpoint `{}` names a next level; only a cache misses", node.name));
            }
            if node.home && !is_cache {
                return Err(format!("{who} home `{}` is not a cache; a directory lives in one", node.name));
            }
        }
        // Every chain ends at an endpoint, and none loops.
        for node in &sys.nodes {
            let mut seen = HashSet::new();
            let mut at = node;
            while !at.next.is_empty() {
                if !seen.insert(at.name.as_str()) {
                    return Err(format!("{who} levels below `{}` form a cycle", node.name));
                }
                at = by_name
                    .get(at.next.as_str())
                    .ok_or(format!("{who} node `{}` names next level `{}`, which is not a node", at.name, at.next))?;
            }
        }
        // The address map: disjoint, line-aligned, inside the address width,
        // each at an endpoint, each coherent one at a home.
        let limit: u128 = 1u128 << ic.address_bits;
        let mut spans: Vec<(u64, u64, &str)> = Vec::new();
        for region in &sys.regions {
            let target = by_name
                .get(region.target.as_str())
                .ok_or(format!("{who} region at {:#x} targets `{}`, which is not a node", region.base, region.target))?;
            if !target.next.is_empty() {
                return Err(format!("{who} region at {:#x} targets cache `{}`; a region ends at an endpoint", region.base, region.target));
            }
            if region.size == 0 {
                return Err(format!("{who} region at {:#x} is empty", region.base));
            }
            if u128::from(region.base) + u128::from(region.size) > limit {
                return Err(format!("{who} region at {:#x} reaches past {} address bits", region.base, ic.address_bits));
            }
            if line != 0 && (region.base % u64::from(line) != 0 || region.size % u64::from(line) != 0) {
                return Err(format!("{who} region at {:#x} is not aligned to the {line}-byte line", region.base));
            }
            if let Some(memory) = memories.get(target.memory.as_str()) {
                if region.size > memory.size_bytes {
                    return Err(format!("{who} region at {:#x} is larger than `{}`", region.base, target.memory));
                }
            }
            if region.uncached && !region.home.is_empty() {
                return Err(format!("{who} region at {:#x} is uncached and names a home", region.base));
            }
            if coherent && !region.uncached {
                if region.home.is_empty() {
                    return Err(format!("{who} region at {:#x} names no home under protocol `{}`", region.base, sys.coherence.protocol));
                }
                let home = by_name
                    .get(region.home.as_str())
                    .ok_or(format!("{who} region at {:#x} names home `{}`, which is not a node", region.base, region.home))?;
                if !home.home {
                    return Err(format!("{who} region at {:#x} names `{}`, which is not declared `(home)`", region.base, region.home));
                }
            } else if !region.home.is_empty() {
                return Err(format!("{who} region at {:#x} names a home and the system is not coherent", region.base));
            }
            spans.push((region.base, region.base + region.size, &region.target));
        }
        spans.sort();
        for pair in spans.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(format!("{who} regions at {:#x} and {:#x} overlap", pair[0].0, pair[1].0));
            }
        }
        // ⚠️ What the coherence contract assumes, required rather than hoped
        // for: every port reaches each coherent region's home (the directory
        // can only order what passes it); a port under a protocol is
        // write-back and write-allocate, since a line's state IS its
        // ownership; it does not prefetch, since a prefetched line would need
        // a state nobody asked for; and a home is not exclusive, since a
        // directory keeps the lines it orders.
        if coherent {
            let ports: Vec<&MemNode> = sys.nodes.iter().filter(|n| !n.core.is_empty()).collect();
            for port in &ports {
                let m = memories[port.memory.as_str()];
                let p = &m.policy;
                if p.write_policy == "write-through" || p.allocate == "no-write-allocate" {
                    return Err(format!("{who} port `{}` is under `{}` and not write-back, write-allocate", port.name, sys.coherence.protocol));
                }
                if !p.prefetch.is_empty() {
                    return Err(format!("{who} port `{}` prefetches under `{}`; a prefetched line has no owner", port.name, sys.coherence.protocol));
                }
            }
            for region in sys.regions.iter().filter(|r| !r.uncached) {
                if let Some(home) = by_name.get(region.home.as_str()) {
                    if memories[home.memory.as_str()].policy.inclusion == "exclusive" {
                        return Err(format!("{who} home `{}` is exclusive; a directory keeps the lines it orders", home.name));
                    }
                    for port in &ports {
                        let mut at = *port;
                        let mut reaches = false;
                        while let Some(next) = by_name.get(at.next.as_str()) {
                            if next.name == home.name { reaches = true; break; }
                            at = next;
                        }
                        if !reaches {
                            return Err(format!("{who} port `{}` does not reach home `{}`", port.name, home.name));
                        }
                    }
                }
            }
        }
        let has_dram = sys.nodes.iter().any(|n| memories.get(n.memory.as_str()).is_some_and(|m| m.kind == "dram"));
        if has_dram && sys.clock_ps == 0 {
            return Err(format!("{who} has a DRAM and no `(clock-ps n)`: its timing is in its own clock, and nothing says what a cycle here is"));
        }
        let ids = cols * rows;
        if coherent && u64::from(ids) > (1u64 << sys.coherence.node_id_bits) {
            return Err(format!("{who} has {ids} places and {} node-id bits", sys.coherence.node_id_bits));
        }
    }
    Ok(())
}

// ---- the manifest ----------------------------------------------------------------

fn js(text: &str) -> String {
    let mut out = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A node's place as one id: row-major over the grid, the numbering both the
/// mesh routers and a CHI home-node id use.
pub fn node_id(ic: &Interconnect, at: (u32, u32)) -> u32 {
    let (cols, _) = ic.topology.grid();
    at.1 * cols + at.0
}

/// `axis.memsys.v1`: every memory system, resolved -- node ids, each core's
/// path to memory, hop counts to the next level, and the address map with its
/// target and home ids -- so that no consumer re-derives what the description
/// already decided.
pub fn emit_memsys_json(document: &Document) -> String {
    let memories: HashMap<&str, &Memory> = document.memories.iter().map(|m| (m.name.as_str(), m)).collect();
    let mut out = String::new();
    out.push_str("{\n  \"schema\": \"axis.memsys.v1\",\n");
    let _ = writeln!(out, "  \"name\": {},", js(&document.extension.name));
    out.push_str("  \"systems\": [");
    for (si, sys) in document.memsystems.iter().enumerate() {
        let Some(ic) = document.interconnects.iter().find(|i| i.name == sys.interconnect) else { continue };
        let (cols, rows) = ic.topology.grid();
        let by_name: HashMap<&str, &MemNode> = sys.nodes.iter().map(|n| (n.name.as_str(), n)).collect();
        out.push_str(if si == 0 { "\n" } else { ",\n" });
        let _ = writeln!(out, "    {{\n      \"name\": {},\n      \"clock_ps\": {},", js(&sys.name), sys.clock_ps);
        let _ = writeln!(
            out,
            "      \"interconnect\": {{\"name\": {}, \"topology\": {}, \"cols\": {cols}, \"rows\": {rows}, \"virtual_channels\": {}, \"buffer_depth\": {}, \"flit_bits\": {}, \"address_bits\": {}, \"hop_cycles\": {}, \"router_cycles\": {}}},",
            js(&ic.name), js(ic.topology.kind()), ic.virtual_channels, ic.buffer_depth, ic.flit_bits,
            ic.address_bits, ic.hop_cycles, ic.router_cycles
        );
        let c = &sys.coherence;
        let _ = writeln!(
            out,
            "      \"coherence\": {{\"protocol\": {}, \"credit_depth\": {}, \"txn_id_bits\": {}, \"node_id_bits\": {}, \"table_depth\": {}, \"features\": [{}]}},",
            js(&c.protocol), c.credit_depth, c.txn_id_bits, c.node_id_bits, c.table_depth,
            c.features.iter().map(|f| js(f)).collect::<Vec<_>>().join(", ")
        );
        out.push_str("      \"nodes\": [");
        for (ni, node) in sys.nodes.iter().enumerate() {
            let m = memories.get(node.memory.as_str());
            let kind = m.map(|m| m.kind.as_str()).unwrap_or("");
            out.push_str(if ni == 0 { "\n" } else { ",\n" });
            let _ = write!(
                out,
                "        {{\"name\": {}, \"id\": {}, \"x\": {}, \"y\": {}, \"memory\": {}, \"kind\": {}, \"core\": {}, \"next\": {}, \"home\": {}",
                js(&node.name), node_id(ic, node.at), node.at.0, node.at.1, js(&node.memory), js(kind),
                js(&node.core), js(&node.next), node.home
            );
            if let Some(next) = by_name.get(node.next.as_str()) {
                let _ = write!(out, ", \"hops_to_next\": {}", ic.topology.hops(node.at, next.at));
            }
            if let Some(m) = m {
                let p = &m.policy;
                let _ = write!(
                    out,
                    ", \"size_bytes\": {}, \"latency_cycles\": {}, \"line_bytes\": {}, \"ways\": {}, \"banks\": {}",
                    m.size_bytes, m.latency_cycles, m.line_bytes, m.ways, m.banks
                );
                if m.line_bytes != 0 {
                    let sets = m.size_bytes / u64::from(m.line_bytes) / u64::from(m.ways.max(1));
                    let _ = write!(
                        out,
                        ", \"sets\": {sets}, \"replacement\": {}, \"write_policy\": {}, \"allocate\": {}, \"mshrs\": {}, \"inclusion\": {}, \"prefetch\": {}, \"prefetch_degree\": {}, \"prefetch_queue\": {}",
                        js(or(&p.replacement, "lru")), js(or(&p.write_policy, "write-back")),
                        js(or(&p.allocate, "write-allocate")), p.mshrs, js(or(&p.inclusion, "nine")),
                        js(&p.prefetch), p.prefetch_degree, p.prefetch_queue
                    );
                }
                if let Some(d) = &p.dram {
                    let t = &d.timing;
                    let _ = write!(
                        out,
                        ", \"dram\": {{\"standard\": {}, \"channels\": {}, \"bus_bytes\": {}, \"ranks\": {}, \"row_bytes\": {}, \"page_policy\": {}, \"tck_ps\": {}, \"tcl\": {}, \"trcd\": {}, \"trp\": {}, \"tras\": {}}}",
                        js(&d.standard), d.channels.max(1), if d.bus_bytes == 0 { 8 } else { d.bus_bytes }, d.ranks.max(1), d.row_bytes,
                        js(or(&d.page_policy, "open")), t.tck_ps, t.tcl, t.trcd, t.trp, t.tras
                    );
                }
            }
            out.push('}');
        }
        out.push_str("\n      ],\n      \"paths\": {");
        let mut first = true;
        for node in sys.nodes.iter().filter(|n| !n.core.is_empty()) {
            let mut chain = vec![js(&node.name)];
            let mut at = node;
            while let Some(next) = by_name.get(at.next.as_str()) {
                chain.push(js(&next.name));
                at = next;
            }
            let _ = write!(out, "{}\n        {}: [{}]", if first { "" } else { "," }, js(&node.core), chain.join(", "));
            first = false;
        }
        out.push_str("\n      },\n      \"address_map\": [");
        for (ri, r) in sys.regions.iter().enumerate() {
            let target_id = by_name.get(r.target.as_str()).map(|n| node_id(ic, n.at)).unwrap_or(0);
            let home_id = by_name.get(r.home.as_str()).map(|n| node_id(ic, n.at).to_string()).unwrap_or("null".into());
            let (tx, ty) = by_name.get(r.target.as_str()).map(|n| n.at).unwrap_or((0, 0));
            out.push_str(if ri == 0 { "\n" } else { ",\n" });
            let _ = write!(
                out,
                "        {{\"base\": {}, \"size\": {}, \"target\": {}, \"target_id\": {target_id}, \"target_x\": {tx}, \"target_y\": {ty}, \"home\": {}, \"home_id\": {home_id}, \"uncached\": {}}}",
                r.base, r.size, js(&r.target), js(&r.home), r.uncached
            );
        }
        out.push_str("\n      ]\n    }");
    }
    out.push_str("\n  ]\n}\n");
    out
}

fn or<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() { default } else { value }
}

// ---- the round trip --------------------------------------------------------------

/// The `defmemory` properties this module owns, as `emit-lisp` writes them.
pub fn emit_lisp_policy(out: &mut String, memory: &Memory) {
    let p = &memory.policy;
    for (key, v) in [("replacement", &p.replacement), ("write-policy", &p.write_policy),
                     ("allocate", &p.allocate), ("inclusion", &p.inclusion), ("prefetch", &p.prefetch)] {
        if !v.is_empty() {
            let _ = writeln!(out, "    ({key} {v})");
        }
    }
    if p.mshrs != 0 {
        let _ = writeln!(out, "    (mshrs {})", p.mshrs);
    }
    if p.prefetch_queue != 0 {
        let _ = writeln!(out, "    (prefetch-queue {})", p.prefetch_queue);
    }
    if p.blocking {
        let _ = writeln!(out, "    (blocking true)");
    }
    if p.prefetch_degree != 0 {
        let _ = writeln!(out, "    (prefetch-degree {})", p.prefetch_degree);
    }
    if let Some(d) = &p.dram {
        if !d.standard.is_empty() {
            let _ = writeln!(out, "    (standard {})", d.standard);
        }
        for (key, v) in [("channels", d.channels), ("bus-bytes", d.bus_bytes), ("ranks", d.ranks), ("row-bytes", d.row_bytes)] {
            if v != 0 {
                let _ = writeln!(out, "    ({key} {v})");
            }
        }
        if !d.page_policy.is_empty() {
            let _ = writeln!(out, "    (page-policy {})", d.page_policy);
        }
        let t = &d.timing;
        let _ = writeln!(
            out,
            "    (timing (tck-ps {}) (tcl {}) (trcd {}) (trp {}) (tras {}))",
            t.tck_ps, t.tcl, t.trcd, t.trp, t.tras
        );
    }
}

/// `definterconnect` and `defmemsys`, as `emit-lisp` writes them.
pub fn emit_lisp_forms(out: &mut String, document: &Document) {
    for ic in &document.interconnects {
        let _ = writeln!(out, "  (definterconnect {}", ic.name);
        let topo = match &ic.topology {
            Topology::Mesh { rows, cols } => format!("(topology mesh (rows {rows}) (cols {cols}))"),
            Topology::Torus { rows, cols } => format!("(topology torus (rows {rows}) (cols {cols}))"),
            Topology::Ring { nodes } => format!("(topology ring (nodes {nodes}))"),
            Topology::Crossbar { ports } => format!("(topology crossbar (ports {ports}))"),
        };
        let _ = writeln!(out, "    {topo}");
        let _ = writeln!(
            out,
            "    (virtual-channels {}) (buffer-depth {}) (flit-bits {}) (address-bits {}) (hop-cycles {}) (router-cycles {}))",
            ic.virtual_channels, ic.buffer_depth, ic.flit_bits, ic.address_bits, ic.hop_cycles, ic.router_cycles
        );
    }
    for sys in &document.memsystems {
        let c = &sys.coherence;
        let _ = writeln!(out, "  (defmemsys {}", sys.name);
        let _ = writeln!(out, "    (interconnect {})", sys.interconnect);
        if sys.clock_ps != 0 {
            let _ = writeln!(out, "    (clock-ps {})", sys.clock_ps);
        }
        let features = if c.features.is_empty() { String::new() } else { format!(" (features {})", c.features.join(" ")) };
        let _ = writeln!(
            out,
            "    (coherence (protocol {}) (credit-depth {}) (txn-id-bits {}) (node-id-bits {}) (table-depth {}){features})",
            c.protocol, c.credit_depth, c.txn_id_bits, c.node_id_bits, c.table_depth
        );
        out.push_str("    (nodes");
        for n in &sys.nodes {
            let _ = write!(out, "\n      ({} (memory {}) (at {} {})", n.name, n.memory, n.at.0, n.at.1);
            if !n.core.is_empty() {
                let _ = write!(out, " (core {})", n.core);
            }
            if !n.next.is_empty() {
                let _ = write!(out, " (next {})", n.next);
            }
            if n.home {
                out.push_str(" (home)");
            }
            out.push(')');
        }
        out.push_str(")\n    (address-map");
        for r in &sys.regions {
            let _ = write!(out, "\n      (region {:#x} {:#x} {}", r.base, r.size, r.target);
            if !r.home.is_empty() {
                let _ = write!(out, " (home {})", r.home);
            }
            if r.uncached {
                out.push_str(" (uncached)");
            }
            out.push(')');
        }
        out.push_str("))\n");
    }
}

// ---- the simulator's tables ------------------------------------------------------

fn c_str(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Each memory system as the tables `memsys_engine.c` runs, and
/// `AXIS_MS_SYSTEMS` over them. Field for field the order
/// `tools/memsys_sim_check.py` writes from the manifest, so the engine the
/// pack carries is configured exactly as the one that gate compared.
pub fn emit_pack_tables(document: &Document) -> String {
    let memories: HashMap<&str, &Memory> = document.memories.iter().map(|m| (m.name.as_str(), m)).collect();
    let mut out = String::new();
    let mut systems = Vec::new();
    for (si, sys) in document.memsystems.iter().enumerate() {
        let Some(ic) = document.interconnects.iter().find(|i| i.name == sys.interconnect) else { continue };
        let index: HashMap<&str, usize> = sys.nodes.iter().enumerate().map(|(i, n)| (n.name.as_str(), i)).collect();
        let _ = writeln!(out, "static const axis_ms_node_cfg AXIS_MS_NODES_{si}[] = {{");
        for node in &sys.nodes {
            let m = memories[node.memory.as_str()];
            let p = &m.policy;
            let kind = match m.kind.as_str() { "dram" => 1, _ if m.line_bytes != 0 => 0, _ => 2 };
            let next = index.get(node.next.as_str()).map_or(-1, |&i| i as i64);
            let sets = if m.line_bytes != 0 { m.size_bytes / u64::from(m.line_bytes) / u64::from(m.ways.max(1)) } else { 0 };
            let repl = match p.replacement.as_str() { "plru" => 1, "fifo" => 2, "random" => 3, _ => 0 };
            let incl = match p.inclusion.as_str() { "inclusive" => 1, "exclusive" => 2, _ => 0 };
            let wb = i32::from(p.write_policy != "write-through");
            let wa = i32::from(p.allocate != "no-write-allocate");
            // Untimed accesses run next-line only, as they always have.
            let kinds: Vec<&str> = p.prefetch.split_whitespace().collect();
            let degree = if kinds.contains(&"next-line") { p.prefetch_degree } else { 0 };
            let pf_kinds = u32::from(kinds.contains(&"next-line"))
                | u32::from(kinds.contains(&"stride")) << 1
                | u32::from(kinds.contains(&"best-offset")) << 2;
            let d = p.dram.clone().unwrap_or_default();
            let _ = writeln!(
                out,
                "  {{{}, {}, {kind}, {next}, {}u, {}u, {}u, {sets}u, {}u, {}u, {repl}, {incl}, {wb}, {wa}, {degree}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {pf_kinds}u, {}u, {}u, {}u, {}u, {}}},",
                c_str(&node.name), c_str(&node.core), node.at.0, node.at.1, m.latency_cycles,
                if m.line_bytes != 0 { m.ways } else { 0 }, m.line_bytes,
                if kind == 1 { m.banks } else { 0 }, d.row_bytes, u32::from(d.page_policy == "closed"),
                d.timing.tck_ps, d.timing.tcl, d.timing.trcd, d.timing.trp,
                p.mshrs, if kinds.is_empty() { 0 } else { p.prefetch_degree.max(1) }, d.channels.max(1), d.bus_bytes,
                p.prefetch_queue, c_str(external_prefetcher(p).unwrap_or(""))
            );
        }
        out.push_str("};\n");
        let _ = writeln!(out, "static const axis_ms_region_cfg AXIS_MS_REGIONS_{si}[] = {{");
        for r in &sys.regions {
            let target = index.get(r.target.as_str()).copied().unwrap_or(0);
            let home = index.get(r.home.as_str()).map_or(-1, |&i| i as i64);
            let _ = writeln!(out, "  {{{}u, {}u, {target}, {}, {home}}},", r.base, r.size, i32::from(r.uncached));
        }
        if sys.regions.is_empty() {
            out.push_str("  {0u, 0u, -1, 0, -1},\n");
        }
        out.push_str("};\n");
        let topo = match ic.topology { Topology::Mesh { .. } => 0, Topology::Torus { .. } => 1, Topology::Ring { .. } => 2, Topology::Crossbar { .. } => 3 };
        let (cols, rows) = ic.topology.grid();
        let protocol = match sys.coherence.protocol.as_str() { "msi" => 1, "mesi" => 2, "moesi" => 3, _ => 0 };
        systems.push(format!(
            "  {{{}, {}u, {topo}, {cols}u, {rows}u, {}u, {}u, {}, AXIS_MS_NODES_{si}, {}, AXIS_MS_REGIONS_{si}, {protocol}}}",
            c_str(&sys.name), sys.clock_ps.max(1), ic.hop_cycles, ic.router_cycles, sys.nodes.len(), sys.regions.len()
        ));
    }
    let _ = writeln!(out, "#define AXIS_MS_SYSTEM_COUNT {}", systems.len());
    if systems.is_empty() {
        out.push_str("static const axis_ms_system_cfg AXIS_MS_SYSTEMS[1] = {{0}};\n");
    } else {
        let _ = writeln!(out, "static const axis_ms_system_cfg AXIS_MS_SYSTEMS[] = {{\n{}\n}};", systems.join(",\n"));
    }
    out
}
