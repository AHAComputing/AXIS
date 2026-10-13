#!/usr/bin/env python3
"""A CPU core and a SIMT core, one clock, one memory system (U3). Gate.

docs/unified_engine_design.md: two engines, the pack simulator's
execution-driven pipeline and the SIMT engine, run as one machine. The
simulator pack steps its machines a cycle at a time (`cycle_cores`); the SIMT
engine steps its own (`axis_simt_cycle`); the SIMT machine adopts the CPU
machine's memory system (`memsys_handle`, `axis_simt_share_memsys`), at its
own port. Both ask it WHEN, so each meets the other's traffic.

Over the SIMT example with one memory system added -- an L1 for each core, a
shared L2, a DRAM whose bus carries one line at a time -- this requires:

  * THE CPU COMPUTES WHAT IT SHOULD: its loop of independent loads leaves the
    sum the program defines, alone and beside the SIMT core;
  * CONTENTION IS SEEN: the CPU's loop takes more cycles beside a SIMT core
    streaming through the same L2 and DRAM than alone;
  * THE LEVELS ARE SHARED: the L2 counts both cores' misses -- more than the
    CPU's alone.

Usage: tools/unified_run_check.py [examples/simt_core.axisl]
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_pack  # noqa: E402
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
from simt_check import Assembler  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CPU_ENTRY, CPU_BASE, LOADS, STRIDE = 0x8000, 0x20000, 400, 1088

ADDED = """
  ; U3 (tools/unified_run_check.py): a CPU core and a SIMT core, each with an
  ; L1, over one L2 and one DRAM.
  (defmemory u3_l1 (kind cache) (size-bytes 4096) (line-bytes 64) (ways 4) (latency-cycles 2)
    (replacement lru) (write-policy write-back) (allocate write-allocate) (mshrs 8))
  (defmemory u3_l2 (kind cache) (size-bytes 32768) (line-bytes 64) (ways 8) (latency-cycles 10)
    (replacement lru) (write-policy write-back) (allocate write-allocate) (inclusion nine) (mshrs 16))
  (defmemory u3_dram (kind dram) (size-bytes 0x100000000) (width-bits 64) (banks 8) (latency-cycles 40)
    (channels 1) (bus-bytes 8) (ranks 1) (row-bytes 2048) (page-policy open)
    (timing (tck-ps 1000) (tcl 10) (trcd 10) (trp 10) (tras 20)))
  (definterconnect u3_xbar (topology crossbar (ports 4)) (virtual-channels 1) (buffer-depth 1)
    (flit-bits 64) (address-bits 48) (hop-cycles 1) (router-cycles 0))
  (defmemsys u3_sys
    (clock-ps 500)
    (interconnect u3_xbar)
    (coherence (protocol none))
    (nodes
      (cpu-l1 (memory u3_l1) (core u3_cpu) (at 0 0) (next u3-l2))
      (simt-l1 (memory u3_l1) (core u3_simt) (at 1 0) (next u3-l2))
      (u3-l2 (memory u3_l2) (at 2 0) (next u3-dram))
      (u3-dram (memory u3_dram) (at 3 0)))
    (address-map (region 0x0 0x100000000 u3-dram)))

  (defcore u3_cpu
    (kind rvmt)
    (implements st32)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute)
    (memory-timing timed))

  (defcore u3_simt
    (kind simt) (implements st32) (issue-width 1)
    (simt (warps 4) (lanes 8) (scheduler rr) (stack 8) (line 64)
      (warp-control (split STSPLIT) (join STJOIN) (pred STPRED) (tmc STTMC) (bar STBAR) (wsync STWSYNC))
      (sysread STCSRR (dst rd) (index (imm 1)))))
"""

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
#include "axis_simt.h"
extern const axis_sim_pack *@SIM@(void);
#define MEM (1u << 21)
static uint8_t mem[MEM];
static uint32_t cpu_len;
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; uint64_t v = 0; if (a + w / 8 <= MEM) memcpy(&v, mem + a, w / 8); return v; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; if (a + w / 8 <= MEM) memcpy(mem + a, &v, w / 8); }
static uint32_t cfetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc >= @ENTRY@ && pc < @ENTRY@ + 4ull * cpu_len; uint32_t w = 0; if (*ok) memcpy(&w, mem + pc, 4); return w;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
static uint32_t sfetch(void *c, uint64_t pc, int *ok) { (void)c; uint32_t w = 0; *ok = pc + 4 <= MEM; if (*ok) memcpy(&w, mem + pc, 4); return w; }
static uint32_t lanes_g;
static axis_simt_machine *SM;
static uint64_t sys_simt(void *c, uint32_t w, uint32_t l, uint32_t i) {
  (void)c; if (i == 0) return (uint64_t)w * lanes_g + l; if (i == 1) return axis_simt_warp_mask(SM, w); if (i == 2) return lanes_g; return 0;
}
static void load(const char *path, uint64_t at) {
  FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
  size_t n = fread(mem + at, 1, MEM - at, f); (void)n; fclose(f);
}
int main(int argc, char **argv) {
  int with_simt = atoi(argv[1]);
  load(argv[2], 0);                  /* the SIMT program and its data */
  load(argv[3], @ENTRY@);            /* the CPU program */
  cpu_len = (uint32_t)atoi(argv[4]);
  const axis_sim_pack *S = @SIM@();
  if (S->abi_version < 5u || !S->cycle_cores) { printf("NOABI\n"); return 0; }
  axis_pack_sim_hooks hooks = { rd, wr, cfetch, on_trap, NULL, NULL };
  void *cpu = S->create(&hooks);
  if (!S->select_core(cpu, "u3_cpu")) { printf("NOCORE\n"); return 1; }
  S->reset(cpu, @ENTRY@u, "st32", NULL, 0);
  S->count_cycles(cpu, 1);
  if (with_simt) {
    axis_simt_hooks h = { rd, wr, sfetch, sys_simt, NULL, NULL, NULL };
    char err[256];
    SM = axis_simt_create("u3_simt", &h, err, sizeof err);
    if (!SM) { printf("ERROR %s\n", err); return 1; }
    lanes_g = axis_simt_lanes(SM);
    if (!axis_simt_share_memsys(SM, S->memsys_handle(cpu))) { printf("NOSHARE\n"); return 1; }
    uint64_t all = lanes_g >= 64 ? ~0ull : ((1ull << lanes_g) - 1);
    for (uint32_t w = 0; w < axis_simt_warps(SM); ++w) axis_simt_start_warp(SM, w, 0, all);
  }
  void *cores[1] = { cpu };
  uint64_t guard = 0;
  while (S->cycle_cores(cores, 1, 1) > 0 && guard++ < 10000000ull)
    if (SM && axis_simt_cycle(SM) < 0) { printf("ERROR %s\n", axis_simt_error(SM)); return 1; }
  uint64_t v[13] = {0};
  int32_t l2 = -1;
  for (int32_t i = 0; i < S->memsys_node_count(cpu); ++i)
    if (!strcmp(S->memsys_node_name(cpu, i), "u3-l2")) l2 = i;
  if (l2 >= 0) S->memsys_stats(cpu, l2, v, 13);
  printf("RUN cycles=%llu sum=%llu l2_misses=%llu simt_cycles=%llu\n", (unsigned long long)S->cycles(cpu),
         (unsigned long long)S->reg(cpu, 9), (unsigned long long)v[1],
         (unsigned long long)(SM ? axis_simt_stats(SM)->cycles : 0));
  if (SM) axis_simt_destroy(SM);
  S->destroy(cpu);
  return 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "simt_core.axisl")
    args = parser.parse_args()
    text = args.corpus.read_text().rstrip()
    assert text.endswith(")")
    text = text[:-1].rstrip() + "\n" + ADDED + ")\n"
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="axis_u3_") as work:
        work = Path(work)
        corpus = work / "u3.axisl"
        corpus.write_text(text)
        manifest = build_pack.build(corpus, work / "packs", only={"lift", "exec", "simt", "sim"})
        root = work / "packs" / manifest["name"]
        ident = build_pack.pack_ident(manifest["name"])
        module = f"u3_{ident}"
        subprocess.run([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / f"{module}.py")],
                       check=True, cwd=AXIS_ROOT, capture_output=True)
        sys.path.insert(0, str(work))
        lift = importlib.import_module(module)
        tests = json.loads(subprocess.run([*axis_prefix(), "emit-roundtrip-json", str(corpus)], capture_output=True,
                                          text=True, check=True, cwd=AXIS_ROOT).stdout)["tests"]
        W = Assembler(lift, tests).w
        # The SIMT core: four warps of eight lanes streaming 128 KiB (four times the
        # L2) at 0x100000, twice.
        simt = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=3, rs1=0, imm=8), W("STMUL", rd=8, rs1=1, rs2=3),
                W("STADDI", rd=3, rs1=0, imm=1024), W("STADDI", rd=4, rs1=0, imm=1024), W("STMUL", rd=3, rs1=3, rs2=4),
                W("STADD", rd=8, rs1=8, rs2=3)]                         # x8 = 0x100000 + 8 * tid: clear of the CPU's lines
        for _ in range(2):
            simt += [W("STADD", rd=2, rs1=8, rs2=0), W("STADDI", rd=18, rs1=0, imm=512)]
            top = len(simt)
            simt += [W("STLW", rd=5, rs1=2, imm=0), W("STADD", rd=6, rs1=6, rs2=5), W("STADDI", rd=2, rs1=2, imm=256),
                     W("STADDI", rd=18, rs1=18, imm=-1)]
            simt += [W("STBNE", rs1=18, rs2=0, imm=(4 * (top - len(simt))) & 0x1fff)]
        simt += [W("STTMC", rs1=0)]
        # The CPU: x5 = CPU_BASE; x9 = sum of LOADS independent loads, STRIDE apart.
        cpu = [W("STADDI", rd=5, rs1=0, imm=1024), W("STADDI", rd=6, rs1=0, imm=CPU_BASE // 1024),
               W("STMUL", rd=5, rs1=5, rs2=6), W("STADDI", rd=18, rs1=0, imm=LOADS),
               W("STADDI", rd=7, rs1=0, imm=STRIDE // 2), W("STADD", rd=7, rs1=7, rs2=7)]
        top = len(cpu)
        cpu += [W("STLW", rd=8, rs1=5, imm=0), W("STADD", rd=9, rs1=9, rs2=8), W("STADD", rd=5, rs1=5, rs2=7),
                W("STADDI", rd=18, rs1=18, imm=-1)]
        cpu += [W("STBNE", rs1=18, rs2=0, imm=(4 * (top - len(cpu))) & 0x1fff)]
        # Memory: each CPU word reads its index + 1, so the sum is known.
        image = bytearray(4 * len(simt))
        for k, word in enumerate(simt):
            image[4 * k:4 * k + 4] = word.to_bytes(4, "little")
        blob = bytearray(CPU_BASE + LOADS * STRIDE + 8 - CPU_ENTRY)
        for k, word in enumerate(cpu):
            blob[4 * k:4 * k + 4] = word.to_bytes(4, "little")
        for k in range(LOADS):
            at = CPU_BASE + k * STRIDE - CPU_ENTRY
            blob[at:at + 4] = (k + 1).to_bytes(4, "little")
        (work / "simt.bin").write_bytes(bytes(image))
        (work / "cpu.bin").write_bytes(bytes(blob))
        src = work / "h.c"
        src.write_text(HARNESS.replace("@SIM@", manifest["libraries"]["sim"]["entry"]).replace("@ENTRY@", str(CPU_ENTRY)))
        libs = [root / "lib" / manifest["libraries"][f]["static"] for f in ("sim", "simt", "exec", "lift")]
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), str(src), *map(str, libs),
                        "-o", str(work / "h")], check=True, capture_output=True)

        def run(with_simt: int) -> dict:
            out = subprocess.run([str(work / "h"), str(with_simt), str(work / "simt.bin"), str(work / "cpu.bin"),
                                  str(len(cpu))], capture_output=True, text=True, check=True).stdout
            line = next((x for x in out.splitlines() if x.startswith(("RUN", "NOABI", "NOCORE", "NOSHARE", "ERROR"))), out)
            if not line.startswith("RUN"):
                failures.append(f"{'with' if with_simt else 'without'} the SIMT core: {line.strip()}")
                return {}
            return {k: int(v) for k, v in (kv.split("=") for kv in line.split()[1:])}

        alone, shared = run(0), run(1)
    want = LOADS * (LOADS + 1) // 2
    for label, r in (("alone", alone), ("beside the SIMT core", shared)):
        if r and r["sum"] != want:
            failures.append(f"the CPU's sum {label} is {r['sum']}, not {want}")
    if alone and shared:
        if not shared["cycles"] > alone["cycles"]:
            failures.append(f"the CPU took {shared['cycles']} cycles beside the SIMT core and {alone['cycles']} alone; "
                            "sharing an L2 and a DRAM bus must cost it something")
        if not shared["l2_misses"] > alone["l2_misses"]:
            failures.append(f"the shared L2 missed {shared['l2_misses']} times with both cores and "
                            f"{alone['l2_misses']} with the CPU alone; it is not shared")
    for f in failures:
        print(f"  FAIL {f}")
    if alone and shared:
        print(f"  the CPU's {LOADS} loads: {alone['cycles']} cycles alone, {shared['cycles']} beside a SIMT core "
              f"streaming the same L2 and DRAM ({shared['simt_cycles']} SIMT cycles); L2 misses {alone['l2_misses']} "
              f"alone, {shared['l2_misses']} shared; sum {want} both ways")
    verdict = "PASS" if not failures else "FAIL"
    print(f"a CPU core and a SIMT core share one clock and one memory: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
