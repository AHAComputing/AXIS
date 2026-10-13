#!/usr/bin/env python3
"""Arch packs compose: two in one program, and one AXIS has never heard of.

A pack is an architecture built as something an external project links. The
property that makes that useful is not that one pack works -- `decode_tree` and
`roundtrip` already prove the tables -- it is that SEVERAL work at once, because
a consumer extending AXIS has a base architecture and its own beside it.

⚠️ The previous exported ABI could not do this, and failed silently. It gives
every description the same symbol names, so linking a base pack and an extension
does not collide: the linker takes the first archive member satisfying each
symbol and never looks at the second. The program gets one architecture and is
told nothing. That is what this gate exists to keep fixed.

Four properties:

* **One name each.** Every library exports exactly one symbol,
  `axis_<facet>_pack_<name>`, and nothing else. Two architectures therefore
  share no name, and neither do two facets of one architecture.
* **Together.** Linked into one program, each answers its own count, its own
  mnemonics, and decodes its own words -- and declines the other's.
* **Unknown to the host.** A host compiled against `axis_pack.h` alone, with no
  architecture's headers and no architecture's name in it, loads a pack by
  reading the name and entry symbol out of the pack's own manifest. The corpus
  used for this is copied somewhere AXIS does not ship it and renamed, so its
  name appears in no AXIS source: it stands for the ISA a downstream project
  brings that this repository was never told about.
* **The same answers, both directions.** Decoding through the pack agrees with
  the roundtrip fixtures, which the encoder and decoder paths already prove,
  and assembling the fixture's operand values back gives the fixture's word. A
  pack that composed beautifully and decoded differently would be worse than
  none.
* **A capability is a library, not a claim.** The first version had capability
  flags and they lied immediately: `AXIS_PACK_HAS_ASSEMBLE` shipped set on every
  pack while the table carried no assemble pointer. Facets are separate
  libraries now -- one either exists on disk or does not -- and a consumer that
  only reads code links the decoder alone.
* **The printed number.** An assembler library carries each operand's transform,
  so `SCVTF`'s `fbits` is 64 minus the field on both sides of the ABI.
* **The disassembler and the assembler agree.** Two libraries, two copies of
  the spelling machinery: the text one writes for a word must be the text the
  other writes for the same instruction and operands, and must parse back. A
  disassembler that drifted from its assembler would be two accounts of one
  description.
* **Text, both ways.** Every fixture is printed to assembly, parsed back, and
  assembled: the same instruction and the same word, or the generated assembler
  and the generated disassembler disagree about their own output. ⚠️ That is
  the property that caught `addi x12, x0, -5` printing back as
  `4294967291` -- the same word and not the same text, because only the
  behavior says an immediate is signed.
* **The lifter agrees with the decoder, up to lanes.** Two libraries, two
  tables: a word must name the same instruction through both. ⚠️ Not the same
  string -- the lift table is lane-expanded (`VADD_VV__l0`) because an executor
  performs each lane, while the decode table carries the instruction the lanes
  elaborate (`VADD_VV`). Strip the suffix and they must agree, and a consumer
  that expected the raw strings to match would be right about every fixed-width
  architecture and wrong about every scalable one.
* **Two machines at once.** The executor libraries are the ones that make this
  worth doing, and they are also the ones whose types forced the contract to
  grow. Two architectures' executors in one program each report their own
  register file and their own state.
* **The adapter loses nothing.** A pack is a translation between the generated
  header's types and the contract's, so the question is whether anything falls
  out in the crossing. The same word is run twice in one binary -- once through
  the pack, once through `axis_exec_step64` directly -- and every register,
  every state value and the whole result must match. ⚠️ Two mutations passed
  before this existed: an executor that dropped its state writes on the way
  back, and one that under-reported its register file. Both are exactly the
  kind of thing an adapter gets wrong and nothing else would notice.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
from build_pack import build  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: A scalable instruction is emitted once per lane and the lanes share a word,
#: so a decoder answers with the instruction and the fixture names a lane of it.
#: The same rule `asm_disasm_check` applies, and for the same reason: one word
#: is one instruction, which for a scalable one is all of its lanes.
LANE_SUFFIX = re.compile(r"__l\d+$")

HOST = r'''
#include <stdio.h>
#include <dlfcn.h>
#include "axis_pack.h"
int main(int argc, char **argv) {
  int bad = 0;
  for (int i = 1; i + 1 < argc; i += 2) {
    void *handle = dlopen(argv[i], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { printf("FAIL dlopen %s: %s\n", argv[i], dlerror()); bad = 1; continue; }
    /* ⚠️ Identity only. Every facet's table begins with the same four
       fields -- version, name, generator, entry -- so a host can read who a
       library is before deciding what it has. Reading past them would call a
       different function in each facet, which is why the prefix is where the
       commonality stops. */
    axis_decode_pack_fn fn = (axis_decode_pack_fn)dlsym(handle, argv[i + 1]);
    if (!fn) { printf("FAIL dlsym %s\n", argv[i + 1]); bad = 1; continue; }
    const axis_decode_pack *p = fn();
    if (p->abi_version != AXIS_PACK_ABI_VERSION) {
      printf("FAIL %s ABI v%u != v%u\n", p->name, p->abi_version, AXIS_PACK_ABI_VERSION);
      bad = 1; continue;
    }
    printf("LOADED %s %s\n", p->name, p->entry);
  }
  return bad;
}
'''

ADAPTER = r"""
/* The pack's executor against the executor it adapts, in one binary. The
   generated header is `static inline`, so including it here gives this
   translation unit its own copy -- which is the point: two ways to the same
   answer, and anything the adapter drops in the crossing shows up. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"
#include "axis_lift.h"
#include "axis_semantics.h"
#include "axis_exec.h"
extern const axis_exec_pack *%(entry)s(void);

#define SLOTS 256
static uint8_t MEM_A[8192], MEM_B[8192];
static uint64_t rd_a(void *c, uint64_t a, uint32_t w) { (void)c; uint64_t v=0; for (uint32_t i=0;i<w/8;++i) v |= (uint64_t)MEM_A[(a+i) %% sizeof MEM_A] << (8*i); return v; }
static void wr_a(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; for (uint32_t i=0;i<w/8;++i) MEM_A[(a+i) %% sizeof MEM_A] = (uint8_t)(v>>(8*i)); }
static uint64_t rd_b(void *c, uint64_t a, uint32_t w) { (void)c; uint64_t v=0; for (uint32_t i=0;i<w/8;++i) v |= (uint64_t)MEM_B[(a+i) %% sizeof MEM_B] << (8*i); return v; }
static void wr_b(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; for (uint32_t i=0;i<w/8;++i) MEM_B[(a+i) %% sizeof MEM_B] = (uint8_t)(v>>(8*i)); }

static const struct { uint32_t word; const char *isa; } WORDS[] = { %(words)s };

int main(void) {
  const axis_exec_pack *X = %(entry)s();
  int adapted = 0;
  for (int k = 0; k < %(count)d; ++k) {
    uint64_t seed[SLOTS];
    for (int i = 0; i < SLOTS; ++i) seed[i] = 0x1111u * (uint64_t)(i + 1) + (uint64_t)k;
    for (size_t i = 0; i < sizeof MEM_A; ++i) MEM_A[i] = MEM_B[i] = (uint8_t)(i * 7 + k);

    /* through the pack, sized as the pack says */
    uint64_t ra[SLOTS]; memcpy(ra, seed, sizeof ra);
    axis_pack_state_entry ps[64];
    int32_t ns = X->state_slots(); if (ns > 64) ns = 64;
    for (int32_t i = 0; i < ns; ++i)
      { ps[i].name = X->state_name(i); ps[i].value = (uint64_t)(i + 3); ps[i].width = X->state_width(i); }
    axis_pack_mem pm = { rd_a, wr_a, NULL };
    axis_pack_exec_result pr;
    X->step(WORDS[k].word, WORDS[k].isa[0] ? WORDS[k].isa : NULL,
            ra, X->register_slots(), &pm, 0x40u, ps, ns, &pr);

    /* and directly, sized generously */
    uint64_t rb[SLOTS]; memcpy(rb, seed, sizeof rb);
    axis_state64_entry es[64];
    for (int32_t i = 0; i < ns; ++i)
      { es[i].name = X->state_name(i); es[i].value = (uint64_t)(i + 3); es[i].width = X->state_width(i); }
    axis_state64 held = { es, (size_t)ns };
    axis_mem64 dm = { rd_b, wr_b, NULL };
    axis_exec_result64 dr = axis_exec_step64(WORDS[k].word,
        WORDS[k].isa[0] ? WORDS[k].isa : NULL, rb, SLOTS, &dm, 0x40u, &held);

    adapted++;
    if (pr.ok != dr.ok || pr.result != dr.result || pr.next_pc != dr.next_pc
        || pr.trapped != dr.trapped || pr.wrote != dr.wrote || pr.dest != dr.dest
        || pr.dest_slot != dr.dest_slot || pr.result_limbs != dr.result_limbs) {
      printf("DIFF word 0x%%08x result/flags\n", WORDS[k].word); return 0;
    }
    /* A value wider than the word crosses as limbs, and dropping them is
       invisible in `result`, which is only the low one. */
    for (uint32_t i = 0; i < dr.result_limbs && i < AXIS_PACK_MAX_LIMBS; ++i)
      if (pr.result_limb[i] != dr.result_limb[i]) {
        printf("DIFF word 0x%%08x limb %%u\n", WORDS[k].word, i); return 0; }
    for (int i = 0; i < SLOTS; ++i)
      if (ra[i] != rb[i]) { printf("DIFF word 0x%%08x register slot %%d: %%llu != %%llu\n",
          WORDS[k].word, i, (unsigned long long)ra[i], (unsigned long long)rb[i]); return 0; }
    for (int32_t i = 0; i < ns; ++i)
      if (ps[i].value != es[i].value) { printf("DIFF word 0x%%08x state %%s: %%llu != %%llu\n",
          WORDS[k].word, ps[i].name, (unsigned long long)ps[i].value,
          (unsigned long long)es[i].value); return 0; }
    if (memcmp(MEM_A, MEM_B, sizeof MEM_A)) { printf("DIFF word 0x%%08x memory\n", WORDS[k].word); return 0; }
  }
  printf("ADAPTED %%d\n", adapted);
  return 0;
}
"""

TEXT = r"""
/* Print, parse, assemble. The generated assembler against the generated
   disassembler: whatever one writes, the other must read back to the same
   instruction and the same word. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "axis_pack.h"
extern const axis_asm_pack *%(entry)s(void);
extern const axis_disasm_pack *%(disasm)s(void);
static const struct { uint32_t word; uint32_t values[32]; } ROWS[] = {
  %(rows)s
};
int main(void) {
  const axis_asm_pack *a = %(entry)s();
  const axis_disasm_pack *d = %(disasm)s();
  int ok = 0, missed = 0, ambiguous = 0, negatives = 0, disassembled = 0;
  for (int k = 0; k < %(count)d; ++k) {
    int32_t index = -1;
    for (int32_t i = 0; i < a->count(); ++i) {
      uint32_t w = 0;
      if (a->assemble(i, ROWS[k].values, &w) && w == ROWS[k].word) { index = i; break; }
    }
    if (index < 0) { continue; }              /* not this pack's to assemble */
    char text[192];
    if (!a->print(index, ROWS[k].values, text, sizeof text)) {
      printf("%%s could not be printed\n", a->mnemonic(index)); return 0;
    }
    int32_t back = -1; uint32_t values[32];
    if (!a->parse(text, &back, values)) {
      printf("%%s printed \"%%s\", which its own parser does not read\n",
             a->mnemonic(index), text);
      return 0;
    }
    uint32_t word = 0;
    if (!a->assemble(back, values, &word)) {
      printf("%%s assembled from its own text failed\n", a->mnemonic(index)); return 0;
    }
    /* ⚠️ The printed number must FIT the field. The round trip alone does not
       say so: an immediate printed unsigned reads back, truncates to the same
       field and assembles to the same word -- `addi x12, x0, 4294967291` is
       the same instruction as `-5` and is not text anyone should publish.
       Breaking the sign extension passed this gate until this check existed. */
    for (int32_t o = 0; o < a->operand_count(index); ++o) {
      uint32_t bits = a->operand_bits(index, o);
      if (!bits || bits >= 64) { continue; }
      int64_t shown = a->operand_printed(index, o, ROWS[k].values[o]);
      int64_t low, high;
      if (a->operand_signed_bits(index, o)) {
        high = (INT64_C(1) << (bits - 1)) - 1; low = -(INT64_C(1) << (bits - 1));
      } else {
        high = (INT64_C(1) << bits) - 1; low = 0;
      }
      /* A transform moves the printed number off the field's own range, and
         legitimately: `fbits` is 64 minus a six-bit field. */
      if (a->operand_printed(index, o, 0) != 0) { continue; }
      if (shown < low || shown > high) {
        printf("%%s printed operand %%s as %%lld, outside a %%u-bit field\n",
               a->mnemonic(index), a->operand_name(index, o),
               (long long)shown, bits);
        return 0;
      }
    }
    if (word != ROWS[k].word) {
      /* ⚠️ Two causes, and they are not the same defect. If the instruction
         the parser chose PRINTS THE SAME TEXT, the description is ambiguous --
         two instructions with one spelling, and no parser can tell them
         apart. If it prints something else, the parser read its own output
         wrongly, which is a bug here. */
      char other[192];
      if (a->print(back, values, other, sizeof other) && !strcmp(other, text)) {
        ambiguous++; continue;
      }
      printf("%%s printed \"%%s\", which parsed back as %%s and assembles to "
             "0x%%08x not 0x%%08x\n",
             a->mnemonic(index), text, a->mnemonic(back), word, ROWS[k].word);
      return 0;
    }
    /* ⚠️ The disassembler's own answer for the same word. Two libraries, two
       copies of the spelling machinery: if they drift, a consumer reading code
       and a consumer writing it disagree about the same description. */
    {
      char shown[192];
      if (!d->disassemble(ROWS[k].word, NULL, shown, sizeof shown)) {
        /* A word two instructions claim decodes to nothing, which the
           disassembler is right to refuse; the ambiguity is counted above. */
      } else if (strcmp(shown, text)) {
        printf("%%s: the disassembler writes \"%%s\" where the assembler writes \"%%s\"\n",
               a->mnemonic(index), shown, text);
        return 0;
      } else {
        disassembled++;
      }
    }
    ok++;

    /* ⚠️ And the same instruction with a negative immediate. Every fixture's
       immediates are small positives, so an immediate printed unsigned printed
       the same digits and this gate could not tell. */
    for (int32_t o = 0; o < a->operand_count(index); ++o) {
      uint32_t sb = a->operand_signed_bits(index, o);
      if (!sb || sb < 2 || sb > 32) { continue; }
      uint32_t values2[32];
      for (int32_t q = 0; q < a->operand_count(index); ++q) { values2[q] = ROWS[k].values[q]; }
      /* -1 in the field. ⚠️ Computed in 64 bits: `UINT32_C(1) << 32` is
         undefined, and `LUI`'s immediate is exactly 32 bits wide. */
      values2[o] = (uint32_t)((UINT64_C(1) << sb) - UINT64_C(1));
      uint32_t w2 = 0;
      if (!a->assemble(index, values2, &w2)) { continue; }
      char t2[192];
      if (!a->print(index, values2, t2, sizeof t2)) { continue; }
      if (a->operand_printed(index, o, values2[o]) != -1) {
        printf("%%s prints a field of all ones as %%lld, not -1\n",
               a->mnemonic(index), (long long)a->operand_printed(index, o, values2[o]));
        return 0;
      }
      int32_t b2 = -1; uint32_t got2[32]; uint32_t w3 = 0;
      if (!a->parse(t2, &b2, got2) || !a->assemble(b2, got2, &w3) || w3 != w2) {
        char other[192];
        if (b2 >= 0 && a->print(b2, got2, other, sizeof other) && !strcmp(other, t2)) {
          ambiguous++; continue;
        }
        printf("%%s with a negative immediate printed \"%%s\" and did not read back\n",
               a->mnemonic(index), t2);
        return 0;
      }
      negatives++;
    }
  }
  /* ⚠️ And what the parser must REFUSE. Every fixture's text is well formed,
     so nothing here exercised a rejection: an out-of-range register number was
     accepted and the gate stayed green. */
  {
    int32_t idx; uint32_t vals[32];
    const char *bad[] = { "", "definitely not an instruction",
                          "add x99999, x0, x0", "add x1, x2," };
    for (int b = 0; b < 4; ++b) {
      if (a->parse(bad[b], &idx, vals)) {
        printf("parser accepted \"%%s\"\n", bad[b]); return 0;
      }
    }
  }
  printf("TEXT %%d %%d %%d %%d %%d\n", ok, missed, ambiguous, negatives, disassembled);
  return 0;
}
"""

MACHINE = r'''
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"
%(externs)s
int main(void) {
%(body)s
  return 0;
}
'''

QUERY = r'''
#include <stdio.h>
#include "axis_pack.h"
%(externs)s
int main(void) {
  const axis_decode_pack *packs[] = { %(calls)s };
  for (int i = 0; i < %(n)d; ++i)
    printf("PACK %%s %%d\n", packs[i]->name, packs[i]->count());
  %(probes)s
  return 0;
}
'''


def run(argv, **kw):
    """Run it, and on failure show what it said.

    ⚠️ This used to swallow stderr, so a pack that would not compile reported a
    `CalledProcessError` naming a temporary path and nothing else. A gate whose
    failures cannot be read is a gate someone will disable.
    """
    done = subprocess.run(argv, capture_output=True, text=True, **kw)
    if done.returncode != 0:
        head = " ".join(str(a) for a in argv[:3])
        print(f"  command failed: {head} ...")
        for line in (done.stderr or done.stdout or "").splitlines()[:12]:
            print(f"    {line}")
        raise subprocess.CalledProcessError(done.returncode, argv,
                                            done.stdout, done.stderr)
    return done


def main() -> int:
    # ⚠️ AArch64 is here because it is the only one of these whose registers
    # are wider than the word. Without it the adapter's limb crossing is never
    # exercised, and an executor pack that dropped `result_limbs` passed.
    corpora = [Path(a) for a in sys.argv[1:] if not a.startswith("--")] or [
        AXIS_ROOT / "examples" / "rv64i.axisl",
        AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl",
    ]
    if len(corpora) < 2:
        print("pack composition: SKIP (needs two descriptions)")
        return DECLINED
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        packs = [build(path, work / "packs") for path in corpora]

        # A description this repository does not ship, under a name that
        # appears in no AXIS source. The pack machinery has never been told
        # about it, which is the whole claim.
        foreign_src = work / "vendor" / "grvlike.axisl"
        foreign_src.parent.mkdir(parents=True, exist_ok=True)
        text = corpora[0].read_text()
        first = text.index("(axis-module ")
        end = text.index("\n", first)
        text = text[:first] + "(axis-module grvlike" + text[end:]
        foreign_src.write_text(text)
        foreign = build(foreign_src, work / "packs")
        packs.append(foreign)

        names = {pack["name"] for pack in packs}
        for pack in packs:
            root = work / "packs" / pack["name"]
            for facet, library in pack["libraries"].items():
                exported = [line.split()[-1] for line in
                            run(["nm", "-g", str(root / "lib" / library["static"])])
                            .stdout.splitlines() if " T " in line]
                if exported not in ([f"_{library['entry']}"], [library["entry"]]):
                    print(f"FAIL {pack['name']}/{facet} exports {exported}, "
                          f"expected only {library['entry']}")
                    failures += 1

        # The ABI header is the contract, so it must not depend on the corpus.
        headers = {(work / "packs" / pack["name"] / "include" / "axis_pack.h").read_bytes()
                   for pack in packs}
        if len(headers) != 1:
            print(f"FAIL axis_pack.h differs between packs ({len(headers)} versions); "
                  "a contract that varies by description is not a contract")
            failures += 1

        # Linked together, each answers for itself.
        chosen = packs[:2]
        source = QUERY % {
            "externs": "\n".join(
                f"extern const axis_decode_pack *{p['libraries']['decode']['entry']}(void);"
                for p in chosen),
            "calls": ", ".join(f"{p['libraries']['decode']['entry']}()" for p in chosen),
            "n": len(chosen),
            "probes": "",
        }
        (work / "q.c").write_text(source)
        include = work / "packs" / chosen[0]["name"] / "include"
        libs = [str(work / "packs" / p["name"] / "lib" / p["libraries"]["decode"]["static"])
                for p in chosen]
        run(["cc", "-std=c11", "-I", str(include), "-o", str(work / "q"),
             str(work / "q.c"), *libs])
        seen = {}
        for line in run([str(work / "q")]).stdout.splitlines():
            _, name, count = line.split()
            seen[name] = int(count)
        for pack in chosen:
            root = work / "packs" / pack["name"]
            want = json.loads((root / "pack.json").read_text())["name"]
            if want not in seen:
                print(f"FAIL {want} did not answer when linked beside "
                      f"{chosen[0]['name']}")
                failures += 1

        # And a host that knows only the contract loads them by manifest.
        (work / "h.c").write_text(HOST)
        run(["cc", "-std=c11", "-I", str(include), "-o", str(work / "h"),
             str(work / "h.c")])
        argv = []
        for pack in packs:
            root = work / "packs" / pack["name"]
            for library in pack["libraries"].values():
                argv += [str(root / "lib" / library["shared"]), library["entry"]]
        out = run([str(work / "h"), *argv]).stdout
        loaded = {line.split()[1] for line in out.splitlines() if line.startswith("LOADED")}
        for pack in packs:
            if pack["name"] not in loaded:
                print(f"FAIL {pack['name']} did not load through the contract alone")
                failures += 1

        # The lifter names the same instruction the decoder does, and two
        # executors coexist. Both are new libraries and both are the reason the
        # contract had to carry shapes rather than only function pointers.
        pair = packs[:2]
        cross = MACHINE % {
            "externs": "\n".join(
                f"extern const axis_lift_pack *{p['libraries']['lift']['entry']}(void);\n"
                f"extern const axis_decode_pack *{p['libraries']['decode']['entry']}(void);\n"
                f"extern const axis_exec_pack *{p['libraries']['exec']['entry']}(void);"
                for p in pair),
            "body": "\n".join(
                f'  {{ const axis_lift_pack *L = {p["libraries"]["lift"]["entry"]}();\n'
                f'    const axis_decode_pack *D = {p["libraries"]["decode"]["entry"]}();\n'
                f'    const axis_exec_pack *X = {p["libraries"]["exec"]["entry"]}();\n'
                f'    printf("M %s %d %d\\n", X->name, X->register_slots(), L->count());\n'
                f'    for (uint32_t w = 0; w < {len(pair)}u; ++w) {{ (void)w; }}\n'
                f'    {{ int agree = 1;\n'
                f'      for (int32_t i = 0; i < D->count(); ++i) {{\n'
                f'        uint32_t word = D->match(i);\n'
                f'        axis_pack_lifted lifted;\n'
                f'        if (!L->lift(word, D->isa(i), &lifted)) continue;\n'
                f'        const char *a = L->mnemonic(lifted.index);\n'
                f'        char base[96]; snprintf(base, sizeof base, "%s", a ? a : "?");\n'
                f'        char *cut = strstr(base, "__l"); if (cut) *cut = 0;\n'
                f'        int32_t j = D->decode(word, D->isa(i));\n'
                f'        const char *b = j < 0 ? "?" : D->mnemonic(j);\n'
                f'        if (!a || !b || strcmp(base, b)) {{ agree = 0;\n'
                f'          printf("X %s lift=%s decode=%s\\n", X->name, base, b); break; }}\n'
                f'      }}\n'
                f'      printf("A %s %d\\n", X->name, agree); }} }}'
                for p in pair),
        }
        (work / "m.c").write_text(cross)
        libs = []
        for p in pair:
            root = work / "packs" / p["name"] / "lib"
            libs += [str(root / p["libraries"][f]["static"])
                     for f in ("lift", "decode", "exec")]
        run(["cc", "-std=c11", "-I", str(include), "-o", str(work / "m"),
             str(work / "m.c"), *libs])
        machines = run([str(work / "m")]).stdout.splitlines()
        named = {line.split()[1] for line in machines if line.startswith("M ")}
        for p in pair:
            if p["name"] not in named:
                print(f"FAIL {p['name']}: its executor did not answer beside "
                      f"{pair[0]['name']}'s")
                failures += 1
        for line in machines:
            if line.startswith("A ") and line.split()[2] != "1":
                print(f"FAIL {line.split()[1]}: the lifter and the decoder name "
                      f"different instructions for the same word")
                failures += 1
            if line.startswith("X "):
                print(f"FAIL {line}")

        checked = 0
        assembled = 0
        adapted = 0
        skipped_lanes = 0
        wide_reached = 0
        round_tripped = 0
        unprintable = 0
        ambiguous = 0
        negatives = 0
        disassembled = 0
        # The adapter against the executor it adapts, in one binary.
        for pack, path in zip(packs, list(corpora) + [foreign_src]):
            root = work / "packs" / pack["name"]
            all_fixtures = json.loads(run(
                [*axis_prefix(), "emit-roundtrip-json", str(path)],
                cwd=AXIS_ROOT).stdout)["tests"]
            # ⚠️ The first sixty, PLUS every instruction with a value wider than
            # the word. The contract carries `result_limb[]` for exactly those,
            # and a draw off the top of the file reached none of them: an
            # adapter that dropped the limbs passed until this line existed.
            lifted = json.loads(run(
                [*axis_prefix(), "emit-lift-json", str(path)],
                cwd=AXIS_ROOT).stdout)
            entries_json = lifted["instructions"] if isinstance(lifted, dict) else lifted
            wide_names = {e["mnemonic"] for e in entries_json
                          if any((op.get("width") or 0) > 64
                                 for op in e.get("operands") or [])}
            fixtures = all_fixtures[:60]
            seen_wide = {f["mnemonic"] for f in fixtures} & wide_names
            for fixture in all_fixtures:
                if len(seen_wide) >= 12:
                    break
                if fixture["mnemonic"] in wide_names and fixture["mnemonic"] not in seen_wide:
                    fixtures.append(fixture)
                    seen_wide.add(fixture["mnemonic"])
            wide_reached += len(seen_wide)
            # ⚠️ And a word that decodes to nothing. Every fixture succeeds, so
            # `ok` is 1 for all of them and an adapter that hardcoded it would
            # have gone unnoticed -- it did, until this was added.
            entries = [f'{{{int(f["encoded"], 16)}u, "{f.get("isa") or ""}"}}'
                       for f in fixtures] + ['{0xffffffffu, ""}']
            words = ", ".join(entries)
            (work / "adapt.c").write_text(ADAPTER % {
                "entry": pack["libraries"]["exec"]["entry"],
                "words": words,
                "count": len(entries),
            })
            run(["cc", "-std=c11", "-DAXIS_IMPL_STUBS", "-I", str(root / "include"),
                 "-o", str(work / "adapt"), str(work / "adapt.c"),
                 str(root / "lib" / pack["libraries"]["exec"]["static"])])
            for line in run([str(work / "adapt")]).stdout.splitlines():
                if line.startswith("DIFF"):
                    print(f"FAIL {pack['name']}: {line}")
                    failures += 1
                elif line.startswith("ADAPTED"):
                    adapted += int(line.split()[1])

        # Text, both ways: print each fixture, parse it back, assemble it.
        for pack, path in zip(packs, list(corpora) + [foreign_src]):
            root = work / "packs" / pack["name"]
            fixtures = json.loads(run(
                [*axis_prefix(), "emit-roundtrip-json", str(path)],
                cwd=AXIS_ROOT).stdout)["tests"]
            # ⚠️ The first two hundred, PLUS every instruction whose printed
            # number differs from its field. `SCVTF_D_X_FIXED` is the only one
            # in the repository and it sits past the cap: breaking the
            # transform's inverse passed this gate until it was included.
            transforming = {e["mnemonic"] for e in json.loads(run(
                [*axis_prefix(), "emit-asm-disasm-json", str(path)],
                cwd=AXIS_ROOT).stdout)["instructions"]
                if any(op.get("asm_transform") for op in e["operands"])}
            chosen = list(fixtures[:200])
            seen_names = {f["mnemonic"] for f in chosen}
            for f in fixtures:
                if f["mnemonic"] in transforming and f["mnemonic"] not in seen_names:
                    chosen.append(f)
                    seen_names.add(f["mnemonic"])
            rows = []
            for f in chosen:
                if LANE_SUFFIX.search(f["mnemonic"]):
                    continue
                values = ", ".join(f'{o["value"]}u' for o in f["operands"]) or "0u"
                rows.append(f'{{ {int(f["encoded"], 16)}u, {{ {values} }} }}')
            if not rows:
                continue
            (work / "text.c").write_text(TEXT % {
                "entry": pack["libraries"]["asm"]["entry"],
                "disasm": pack["libraries"]["disasm"]["entry"],
                "rows": ",\n  ".join(rows),
                "count": len(rows),
            })
            run(["cc", "-std=c11", "-I", str(root / "include"), "-o",
                 str(work / "text"), str(work / "text.c"),
                 str(root / "lib" / pack["libraries"]["asm"]["static"]),
                 str(root / "lib" / pack["libraries"]["disasm"]["static"]),
                 str(root / "lib" / pack["libraries"]["decode"]["static"])])
            for line in run([str(work / "text")]).stdout.splitlines():
                if line.startswith("TEXT"):
                    round_tripped += int(line.split()[1])
                    unprintable += int(line.split()[2])
                    ambiguous += int(line.split()[3])
                    negatives += int(line.split()[4])
                    disassembled += int(line.split()[5])
                else:
                    print(f"FAIL {pack['name']}: {line}")
                    failures += 1

        # The pack decodes what the proven tables decode.
        for pack, path in zip(packs, list(corpora) + [foreign_src]):
            fixtures = json.loads(run(
                [*axis_prefix(), "emit-roundtrip-json", str(path)],
                cwd=AXIS_ROOT).stdout)["tests"]
            root = work / "packs" / pack["name"]
            # Decode, and then assemble the operand values back. The second
            # is what `AXIS_PACK_HAS_ASSEMBLE` promises, and the flag went out
            # set on every pack before anything behind it existed.
            lines = []
            for f in fixtures[:120]:
                word = int(f["encoded"], 16)
                # ⚠️ A lane fixture carries operands the instruction does not:
                # `VADD_VV__l0` lists `vs1__l0` beside `vs1`, which are
                # elaboration artifacts rather than encoded fields. The pack
                # carries the instruction, so only the instruction's own
                # fixtures can be assembled through it. Counted, not dropped.
                if LANE_SUFFIX.search(f["mnemonic"]):
                    skipped_lanes += 1
                    lines.append(
                        f'  {{ int32_t i = p->decode({word}u, "{f.get("isa") or ""}");'
                        f' printf("D %s\\n", i < 0 ? "?" : p->mnemonic(i)); }}')
                    continue
                values = ", ".join(
                    f'{operand["value"]}u' for operand in f["operands"]) or "0u"
                lines.append(
                    f'  {{ int32_t i = p->decode({word}u, "{f.get("isa") or ""}");'
                    f' printf("D %s\\n", i < 0 ? "?" : p->mnemonic(i));'
                    f' uint32_t vals[] = {{ {values} }}; uint32_t w = 0;'
                    f' if (i >= 0)'
                    f' printf("A %d\\n", a->assemble(i, vals, &w) && w == {word}u ? 1 : 0); }}')
            probe = "\n".join(lines)
            src = QUERY % {
                "externs": (
                    f"extern const axis_decode_pack *{pack['libraries']['decode']['entry']}(void);\n"
                    f"extern const axis_asm_pack *{pack['libraries']['asm']['entry']}(void);"),
                "calls": f"{pack['libraries']['decode']['entry']}()",
                "n": 1,
                "probes": (f"const axis_decode_pack *p = packs[0];\n"
                           f"const axis_asm_pack *a = {pack['libraries']['asm']['entry']}();\n"
                           f"{probe}"),
            }
            (work / "d.c").write_text(src)
            run(["cc", "-std=c11", "-I", str(root / "include"), "-o", str(work / "d"),
                 str(work / "d.c"),
                 str(root / "lib" / pack["libraries"]["decode"]["static"]),
                 str(root / "lib" / pack["libraries"]["asm"]["static"])])
            output = run([str(work / "d")]).stdout.splitlines()
            got = [line.split(maxsplit=1)[1] for line in output if line.startswith("D ")]
            rebuilt = [line.split()[1] for line in output if line.startswith("A ")]
            wrong = sum(1 for answer in rebuilt if answer != "1")
            if wrong:
                print(f"FAIL {pack['name']}: {wrong} fixture(s) do not assemble "
                      f"back to their own word through the pack")
                failures += 1
            assembled += len(rebuilt)
            for fixture, answer in zip(fixtures[:120], got):
                checked += 1
                if answer != LANE_SUFFIX.sub("", fixture["mnemonic"]):
                    print(f"FAIL {pack['name']}: {fixture['encoded']} decodes to "
                          f"{answer} through the pack, "
                          f"{LANE_SUFFIX.sub('', fixture['mnemonic'])} through AXIS")
                    failures += 1

    print(f"{len(packs)} pack(s) built, linked together and loaded by manifest; "
          f"{checked} fixture(s) decoded and {assembled} assembled back through "
          f"them, {failures} failure(s)")
    print(f"  {round_tripped} fixture(s) printed to text, parsed back and "
          f"assembled to the same word, {negatives} of them again with a "
          f"negative immediate; {disassembled} of them written identically "
          f"by the disassembler"
          + (f"; {unprintable} whose text the parser did not match"
             if unprintable else ""))
    # ⚠️ A description that spells two instructions the same way. Counted, not
    # passed over: 116 RISC-V instructions were in this state -- six rounding
    # modes per float operation, all printing `fadd.s $rd, $rs1, $rs2` -- and
    # naming the mode in the assembly fixed them. What remains is AArch64's
    # `w`/`x` views, where a class is a window on a file and the description
    # states one spelling per FILE.
    if ambiguous:
        print(f"  {ambiguous} whose printed text another instruction also "
              f"prints: the description spells them the same way, and no "
              f"parser can tell them apart")
    print(f"  {adapted} word(s) run through the pack and through the executor "
          f"directly, register for register, {wide_reached} of them carrying a "
          f"value wider than the word")
    if skipped_lanes:
        print(f"  {skipped_lanes} lane fixture(s) decoded but not assembled: a "
              f"lane's operands are elaboration artifacts, and the pack carries "
              f"the instruction they elaborate")
    print("  one of them under a name no AXIS source contains: "
          f"{foreign['name']}")
    print("pack composition:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
