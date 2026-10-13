//! State-capsule layout resolution (personality design stage P1).
//!
//! A personality's capsule is the ordered architectural state that migrates
//! between personalities. This module resolves capsule entries against the
//! implemented ISA's declared register surface into a canonical byte layout
//! (little-endian, densely packed in capsule order) and pins that layout with
//! a sha256 `layout_hash` so RTL checkpoint logic, cosim harnesses, and
//! `axis_exec` agree on the format by hash rather than by convention.
//!
//! The canonical layout description hashed is layout-only (no personality
//! name or discipline), so migratable personalities share a hash:
//!
//! ```text
//! axis.state-capsule.v1|<name>[<count>]x<width>@<offset>;...
//! ```
//!
//! `tools/migrate_vs_whole.py` re-derives this string from the emitted
//! manifest and re-hashes it, proving the manifest is internally consistent
//! and the format is reproducible outside this crate.

use crate::ast::{Isa, Personality};

/// One declared register group from `isa.registers`, e.g. `x[32]:i32`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterGroup {
    pub name: String,
    pub count: u32,
    pub width_bits: u32,
}

/// The in-flight writes an exposed-latency machine carries (stage B3).
///
/// Under `hazards exposed` a result becomes visible some packets after it
/// issues, so between those two moments it is architectural state that lives
/// nowhere in the register file. A capsule that omits it cannot restore a
/// checkpoint taken in the shadow, and a migration across one would silently
/// drop results — which is why this is part of the layout and therefore part
/// of the hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelayQueue {
    /// Packet boundaries a write can still be waiting on: `max_latency - 1`.
    /// Zero means every latency is 1, the machine has no shadow, and no queue
    /// is emitted — an all-latency-1 exposed machine *is* an interlocked one.
    pub stages: u32,
    /// Writes one packet can put in flight, summed over its slots.
    pub entries_per_stage: u32,
}

/// One in-flight write, as bytes in a capsule.
///
/// ```text
///   +0  valid      u8     (0 = empty entry)
///   +1  reserved   u8[3]
///   +4  location   u32    flat register slot, as `axis_lift.register_slot`
///   +8  value      u64    the pending value, little-endian
/// ```
///
/// Sixteen bytes with three reserved is a choice, and a pinned ABI has to make
/// one; what matters is that it is written down and hashed rather than agreed
/// by convention. The 64-bit value field is why an exposed machine's registers
/// are validated to fit in 64 bits.
pub const DELAY_ENTRY_BYTES: u32 = 16;

/// The capsule entry name the delay queue occupies. It is not a register
/// group, which is why it is spelled like nothing an ISA may declare.
pub const DELAY_ENTRY_NAME: &str = "__delay";

/// One capsule entry resolved to its byte layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleEntry {
    pub name: String,
    pub count: u32,
    pub width_bits: u32,
    pub byte_offset: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleLayout {
    pub entries: Vec<CapsuleEntry>,
    pub total_bytes: u32,
}

/// Parse one `isa.registers` declaration: `name`, `name[count]`,
/// `name:iW`, or `name[count]:iW`. Width defaults to 32.
pub fn parse_register_group(raw: &str) -> Result<RegisterGroup, String> {
    let raw = raw.trim();
    let (head, width_bits) = match raw.rsplit_once(':') {
        Some((head, ty)) => {
            let ty = ty.trim();
            let width = ty
                .strip_prefix('i')
                .and_then(|digits| digits.parse::<u32>().ok())
                .ok_or_else(|| format!("register `{raw}` has malformed type `{ty}`"))?;
            (head.trim(), width)
        }
        None => (raw, 32),
    };
    let (name, count) = match head.split_once('[') {
        Some((name, rest)) => {
            let digits = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("register `{raw}` has unterminated `[`"))?;
            let count = digits
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("register `{raw}` has malformed count `{digits}`"))?;
            (name.trim(), count)
        }
        None => (head, 1),
    };
    if name.is_empty() {
        return Err(format!("register `{raw}` has an empty name"));
    }
    if count == 0 {
        return Err(format!("register `{raw}` count must be positive"));
    }
    if width_bits == 0 || width_bits % 8 != 0 {
        return Err(format!(
            "register `{raw}` width {width_bits} must be a positive multiple of 8 \
             (capsule layouts are byte-addressed)"
        ));
    }
    Ok(RegisterGroup {
        name: name.to_string(),
        count,
        width_bits,
    })
}

/// Parse a capsule entry: `name` or `name[count]` (no type — the width comes
/// from the ISA declaration the entry resolves against).
fn parse_capsule_entry(raw: &str) -> Result<(String, Option<u32>), String> {
    let raw = raw.trim();
    if raw.contains(':') {
        return Err(format!(
            "capsule entry `{raw}` must not carry a type; widths come from the isa registers"
        ));
    }
    match raw.split_once('[') {
        Some((name, rest)) => {
            let digits = rest
                .strip_suffix(']')
                .ok_or_else(|| format!("capsule entry `{raw}` has unterminated `[`"))?;
            let count = digits
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("capsule entry `{raw}` has malformed count `{digits}`"))?;
            Ok((name.trim().to_string(), Some(count)))
        }
        None => Ok((raw.to_string(), None)),
    }
}

/// Resolve a personality's capsule against its ISA into a byte layout.
/// An empty capsule defaults to the ISA's full declared register surface.
///
/// `delay` appends the in-flight writes of an exposed-latency machine after
/// the register groups. Passing `None` reproduces the layout exactly as it was
/// before stage B3, so every existing capsule and every existing hash is
/// unchanged.
pub fn resolve_capsule(
    isa: &Isa,
    personality: &Personality,
    delay: Option<&DelayQueue>,
) -> Result<CapsuleLayout, String> {
    let groups: Vec<RegisterGroup> = isa
        .registers
        .iter()
        .map(|raw| parse_register_group(raw))
        .collect::<Result<_, _>>()
        .map_err(|err| format!("isa `{}`: {err}", isa.name))?;

    let requested: Vec<(String, Option<u32>)> = if personality.capsule.is_empty() {
        groups
            .iter()
            .map(|group| (group.name.clone(), Some(group.count)))
            .collect()
    } else {
        personality
            .capsule
            .iter()
            .map(|raw| parse_capsule_entry(raw))
            .collect::<Result<_, _>>()
            .map_err(|err| format!("personality `{}`: {err}", personality.name))?
    };

    let mut entries = Vec::new();
    let mut offset: u32 = 0;
    let mut seen = std::collections::HashSet::new();
    for (name, count) in requested {
        if !seen.insert(name.clone()) {
            return Err(format!(
                "personality `{}` capsule lists `{name}` more than once",
                personality.name
            ));
        }
        let group = groups
            .iter()
            .find(|group| group.name == name)
            .ok_or_else(|| {
                format!(
                    "personality `{}` capsule entry `{name}` is not a register of isa `{}`",
                    personality.name, isa.name
                )
            })?;
        if let Some(count) = count {
            if count != group.count {
                return Err(format!(
                    "personality `{}` capsule entry `{name}[{count}]` does not match \
                     isa `{}` declaration `{name}[{}]` (partial groups are not portable)",
                    personality.name, isa.name, group.count
                ));
            }
        }
        let bytes = group.count * (group.width_bits / 8);
        entries.push(CapsuleEntry {
            name: group.name.clone(),
            count: group.count,
            width_bits: group.width_bits,
            byte_offset: offset,
        });
        offset += bytes;
    }
    if let Some(delay) = delay {
        if delay.stages > 0 && delay.entries_per_stage > 0 {
            entries.push(CapsuleEntry {
                name: DELAY_ENTRY_NAME.to_string(),
                count: delay.stages * delay.entries_per_stage,
                width_bits: DELAY_ENTRY_BYTES * 8,
                byte_offset: offset,
            });
            offset += delay.stages * delay.entries_per_stage * DELAY_ENTRY_BYTES;
        }
    }
    Ok(CapsuleLayout {
        entries,
        total_bytes: offset,
    })
}

/// The canonical layout description whose sha256 is the `layout_hash`.
/// Deliberately layout-only (no personality name or discipline): consumers
/// match checkpoint formats by hash, and two personalities are migratable
/// exactly when their layout hashes are equal.
pub fn canonical_layout(layout: &CapsuleLayout) -> String {
    let entries = layout
        .entries
        .iter()
        .map(|entry| {
            format!(
                "{}[{}]x{}@{}",
                entry.name, entry.count, entry.width_bits, entry.byte_offset
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    format!("axis.state-capsule.v1|{entries}")
}

pub fn layout_hash(layout: &CapsuleLayout) -> String {
    sha256_hex(canonical_layout(layout).as_bytes())
}

/// Two layouts are migratable iff they are identical (same groups, counts,
/// widths, and therefore offsets) — the capsule bytes of one deserialize
/// exactly into the other.
pub fn layouts_migratable(a: &CapsuleLayout, b: &CapsuleLayout) -> bool {
    a == b
}

/// A shared group name with mismatched count/width across two layouts is a
/// spec error, not a silent "not migratable": the same architectural name
/// must mean the same state everywhere in one document.
pub fn layout_conflict(a: &CapsuleLayout, b: &CapsuleLayout) -> Option<String> {
    for entry_a in &a.entries {
        for entry_b in &b.entries {
            if entry_a.name == entry_b.name
                && (entry_a.count != entry_b.count || entry_a.width_bits != entry_b.width_bits)
            {
                return Some(format!(
                    "capsule group `{}` declared as [{}]x{} vs [{}]x{}",
                    entry_a.name,
                    entry_a.count,
                    entry_a.width_bits,
                    entry_b.count,
                    entry_b.width_bits
                ));
            }
        }
    }
    None
}

// --- sha256 (FIPS 180-4), in-crate: the AXIS crate is dependency-free. ---

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_hex(message: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut data = message.to_vec();
    let bit_len = (message.len() as u64) * 8;
    data.push(0x80);
    while data.len() % 64 != 56 {
        data.push(0);
    }
    data.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h.iter().map(|word| format!("{word:08x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Discipline, Personality};

    fn isa() -> Isa {
        Isa {
            name: "rv32_axis".to_string(),
            registers: vec!["x[32]:i32".to_string(), "pc:i32".to_string()],
            ..Isa::default()
        }
    }

    fn personality(capsule: &[&str]) -> Personality {
        Personality {
            name: "scalar1".to_string(),
            mode: String::new(),
            implements: "rv32_axis".to_string(),
            discipline: Discipline::default(),
            capsule: capsule.iter().map(|entry| entry.to_string()).collect(),
            ..Personality::default()
        }
    }

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // > one 64-byte block
        assert_eq!(
            sha256_hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn resolves_explicit_capsule_with_offsets() {
        let layout = resolve_capsule(&isa(), &personality(&["x[32]", "pc"]), None).unwrap();
        assert_eq!(layout.entries.len(), 2);
        assert_eq!(layout.entries[0].byte_offset, 0);
        assert_eq!(layout.entries[1].byte_offset, 128);
        assert_eq!(layout.total_bytes, 132);
    }

    #[test]
    fn empty_capsule_defaults_to_full_register_surface() {
        let layout = resolve_capsule(&isa(), &personality(&[]), None).unwrap();
        assert_eq!(layout.total_bytes, 132);
    }

    #[test]
    fn rejects_unknown_group_and_partial_group() {
        assert!(resolve_capsule(&isa(), &personality(&["f[32]"]), None)
            .unwrap_err()
            .contains("not a register"));
        assert!(resolve_capsule(&isa(), &personality(&["x[16]"]), None)
            .unwrap_err()
            .contains("partial groups"));
    }

    #[test]
    fn canonical_layout_is_reproducible() {
        let p = personality(&["x[32]", "pc"]);
        let layout = resolve_capsule(&isa(), &p, None).unwrap();
        assert_eq!(
            canonical_layout(&layout),
            "axis.state-capsule.v1|x[32]x32@0;pc[1]x32@128"
        );
        assert_eq!(layouts_migratable(&layout, &layout.clone()), true);
    }
}
