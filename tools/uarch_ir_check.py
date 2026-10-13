#!/usr/bin/env python3
"""A machine can be described openly and modelled privately. Gate.

A microarchitecture is mostly POLICY, and policy is not declarable. If AXIS is
to host a stack where some models are open and some are a vendor's, it needs a
boundary that carries three things it does not own:

  * **which implementation** is meant to time a core, because the geometry is
    not the whole machine;
  * **whatever that implementation's knobs are**, transported intact and not
    interpreted -- AXIS has never heard of them and improving them would be
    editing a machine it cannot read;
  * **what kind of number** the result would be. A closed model's cycle count
    and a count measured against silicon are different claims.

`emit-uarch-json` is that boundary: `axis.uarch.v1`, a MACHINE standing alone.
It is separate from `emit-json` on purpose -- that artifact is the whole
document, and a vendor describing a machine should not have to ship an
instruction set to do it.

What this holds:

  * **the schema is named and versioned**, like every other artifact here;
  * **opaque parameters survive verbatim** through the IR and through a Lisp
    round trip. A dropped vendor setting means a closed model runs on defaults
    and reports a number for a machine nobody configured;
  * **vendor keys are namespaced**, so two vendors cannot collide;
  * **provenance is carried and never invented**: a machine that declares
    `modelled` does not come back `measured`, and one that says nothing comes
    back `declared` rather than blank;
  * ⚠️ **a core naming a model the library is not is REFUSED.** This is the
    property the whole boundary exists for. Selecting it anyway would hand
    back the built-in pipeline's answer for somebody else's machine, and a
    plausible wrong number is worse than a refusal. The library says which
    model would have to be supplied.

Usage: tools/uarch_ir_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

HARNESS = r"""
/* A host meeting a machine it cannot be. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c;(void)a;(void)w; return 0; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c;(void)a;(void)v;(void)w; }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) { (void)c;(void)pc; *ok = 1; return %(word)uu; }

/* A stand-in for somebody else's model: it counts what it was handed and
   charges an implausible flat rate, so the number it returns cannot be
   confused with one this library could have produced. */
static int32_t STANDIN_SEEN;
static uint64_t STANDIN_CYCLES;
static void *standin_create(const axis_sim_core *core) {
  (void)core; STANDIN_SEEN = 0; STANDIN_CYCLES = 0; return &STANDIN_CYCLES;
}
static void standin_destroy(void *state) { (void)state; }
static void standin_account(void *state, const axis_uarch_event *event) {
  (void)event; STANDIN_SEEN++; *(uint64_t *)state += 1000u;
}
static uint64_t standin_cycles(const void *state) { return *(const uint64_t *)state; }
static const char *standin_provenance(void) { return "modelled"; }
static const axis_uarch_pack STANDIN = {
  1u, "%(model)s", "stand-in", standin_create, standin_destroy,
  standin_account, standin_cycles, standin_provenance
};
/* A model no core asks for. Registering it must report zero. */
static const axis_uarch_pack NOBODY = {
  1u, "no-such-model", "stand-in", standin_create, standin_destroy,
  standin_account, standin_cycles, standin_provenance
};

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->core_model || !S->core_provenance || !S->register_model) { printf("NOMODELS\n"); return 0; }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, NULL, NULL, NULL };
  for (int32_t i = 0; i < S->core_count(); ++i) {
    void *m = S->create(&hooks);
    if (!m) { printf("NOMACHINE\n"); return 1; }
    int32_t took = S->select_core(m, S->core_name(i));
    printf("CORE %%s model %%s provenance %%s selected %%d\n",
           S->core_name(i),
           S->core_model(i) && S->core_model(i)[0] ? S->core_model(i) : "-",
           S->core_provenance(i) ? S->core_provenance(i) : "-", took);
    S->destroy(m);
  }
  /* ⚠️ And a refusal must leave the machine ALONE. A host that asked for a
     model it does not have and was told no must still be on whatever it was
     on, not on a pipeline that answered in its place.

     ⚠️ Before the model is registered, or it is not a refusal at all: once
     the implementation is present the core selects, which is the point of
     the rest of this program. */
  void *m = S->create(&hooks);
  int32_t first = -1, second = -1;
  for (int32_t i = 0; i < S->core_count(); ++i) {
    if (S->core_model(i) && S->core_model(i)[0]) { second = i; }
    else if (first < 0) { first = i; }
  }
  if (first >= 0 && second >= 0) {
    printf("KEPT %%d %%d\n", S->select_core(m, S->core_name(first)),
           S->select_core(m, S->core_name(second)));
  }

  /* ⚠️ A STAND-IN for a closed model. It is deliberately not a plausible
     machine: it charges a flat 1000 cycles an instruction, so if the answer
     comes back as anything the built-in pipeline could have produced then
     the built-in pipeline produced it. A realistic fake would make the two
     indistinguishable, which is the one thing this must not be. */
  int32_t wanted = S->register_model(&STANDIN);
  int32_t typo = S->register_model(&NOBODY);
  printf("REGISTER %%d %%d\n", wanted, typo);
  for (int32_t i = 0; i < S->core_count(); ++i) {
    if (!S->core_model(i) || !S->core_model(i)[0]) { continue; }
    void *m = S->create(&hooks);
    int32_t took = S->select_core(m, S->core_name(i));
    S->reset(m, 0u, NULL, NULL, 0);
    S->count_cycles(m, 1);
    for (int32_t k = 0; k < 4; ++k) { S->step(m); }
    printf("BOUND %%s selected %%d cycles %%llu seen %%d source %%s\n",
           S->core_name(i), took, (unsigned long long)S->cycles(m), STANDIN_SEEN,
           S->timing_source && S->timing_source(m) && S->timing_source(m)[0]
             ? S->timing_source(m) : "-");
    S->destroy(m);
  }

  S->destroy(m);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    ir = json.loads(run_cmd([*axis_prefix(), "emit-uarch-json",
                             str(axis_file)]).stdout)
    checks = failures = 0

    checks += 1
    if ir.get("schema") != "axis.uarch.v1":
        print(f"  FAIL {name}: the interchange format calls itself "
              f"{ir.get('schema')!r}; an artifact a vendor ships has to say "
              f"what it is and which version of it")
        failures += 1

    cores = ir.get("cores") or []
    if not cores:
        print(f"  {name}: DECLINED the description declares no core")
        return 0, 0

    # Provenance is a closed vocabulary, present on every core.
    for core in cores:
        checks += 1
        if core.get("provenance") not in ("declared", "measured", "modelled"):
            print(f"  FAIL {name}: core `{core['name']}` reports provenance "
                  f"{core.get('provenance')!r}; a number whose kind is not "
                  f"stated is free text with a decimal point")
            failures += 1

    foreign = [core for core in cores if core.get("model")]
    opaque = [core for core in cores if core.get("vendor")]
    if not foreign or not opaque:
        print(f"  {name}: DECLINED no core names an external model and "
              f"carries parameters for it, so there is no open/closed seam "
              f"here to check")
        return checks, failures

    # ⚠️ Opaque parameters survive a LISP ROUND TRIP. AXIS re-emits
    # descriptions, and a vendor's setting dropped on the way through is a
    # closed model quietly running on defaults.
    rewritten = work / f"{name}.rt.axisl"
    rewritten.write_text(run_cmd([*axis_prefix(), "emit-lisp",
                                  str(axis_file)]).stdout)
    again = json.loads(run_cmd([*axis_prefix(), "emit-uarch-json",
                                str(rewritten)]).stdout)
    by_name = {core["name"]: core for core in again.get("cores") or []}
    for core in foreign:
        checks += 1
        mirror = by_name.get(core["name"])
        if mirror is None or mirror.get("vendor") != core.get("vendor"):
            print(f"  FAIL {name}: core `{core['name']}` carried "
                  f"{core.get('vendor')} and came back through a round trip "
                  f"as {mirror.get('vendor') if mirror else None}")
            failures += 1
        checks += 1
        if mirror is not None and mirror.get("model") != core.get("model"):
            print(f"  FAIL {name}: core `{core['name']}` asked for model "
                  f"{core.get('model')!r} and came back asking for "
                  f"{mirror.get('model')!r}")
            failures += 1

    for core in opaque:
        for key in core["vendor"]:
            checks += 1
            if "." not in key:
                print(f"  FAIL {name}: vendor parameter `{key}` on core "
                      f"`{core['name']}` is not namespaced; two vendors' "
                      f"settings would collide with nobody to arbitrate")
                failures += 1

    # ⚠️ THE PROPERTY: the library refuses to be a machine it is not.
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    pack = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return checks, failures
    # A word the description can decode, so the stand-in model is handed real
    # events rather than nothing at all.
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    word = int(tests[0]["encoded"], 16) if tests else 0
    source = HARNESS % {"sim": manifest["libraries"]["sim"]["entry"],
                        "model": foreign[0]["model"], "word": word}
    root = work / "packs" / pack
    (work / f"{pack}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / pack), str(work / f"{pack}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / pack)], capture_output=True, text=True)
    if done.returncode != 0 or "NOMODELS" in done.stdout:
        print(f"  FAIL {name}: the simulator library reports no models")
        return checks, failures + 1

    said, kept = {}, None
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 8 and parts[0] == "CORE":
            said[parts[1]] = (parts[3], parts[5], int(parts[7]))
        elif len(parts) == 3 and parts[0] == "KEPT":
            kept = (int(parts[1]), int(parts[2]))

    for core in cores:
        row = said.get(core["name"])
        checks += 1
        if row is None:
            print(f"  FAIL {name}: the library reported nothing for core "
                  f"`{core['name']}`")
            failures += 1
            continue
        # ⚠️ An external PREDICTOR is refused the same way until registered
        # (O8); `tage_check.py` holds that one's registration.
        wants = bool(core.get("model"))
        outsourced = "." in (core.get("predictor") or "")
        if outsourced and not wants:
            checks += 1
            if row[2] != 0:
                print(f"  FAIL {name}: core `{core['name']}` asks for predictor "
                      f"`{core['predictor']}`, which nobody registered, and this library "
                      f"selected it anyway")
                failures += 1
            continue
        if wants and row[2] != 0:
            print(f"  FAIL {name}: core `{core['name']}` asks to be timed by "
                  f"`{core['model']}` and this library selected it anyway; it "
                  f"would have answered with its own pipeline for somebody "
                  f"else's machine")
            failures += 1
        elif not wants and row[2] != 1:
            print(f"  FAIL {name}: core `{core['name']}` asks for no external "
                  f"model and was refused")
            failures += 1
        # The library has to SAY what it would need.
        checks += 1
        if wants and row[0] != core["model"]:
            print(f"  FAIL {name}: core `{core['name']}` needs "
                  f"{core['model']!r} and the library reports {row[0]!r}; a "
                  f"host told only `no` cannot go and find one")
            failures += 1
        checks += 1
        if row[1] != core.get("provenance"):
            print(f"  FAIL {name}: core `{core['name']}` declares provenance "
                  f"{core.get('provenance')!r} and the library reports "
                  f"{row[1]!r}")
            failures += 1

    # ⚠️ Registration reports how many cores asked for the model. A model
    # nobody names is a typo or a model built for another description, and
    # accepting it silently means every later refusal is unexplained.
    registered = None
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "REGISTER":
            registered = (int(parts[1]), int(parts[2]))
    checks += 1
    if registered is None or registered[0] < 1:
        print(f"  FAIL {name}: registering `{foreign[0]['model']}` reported "
              f"{registered[0] if registered else '?'} core(s) wanting it, "
              f"and {len(foreign)} do")
        failures += 1
    checks += 1
    if registered is not None and registered[1] != 0:
        print(f"  FAIL {name}: registering a model no core names reported "
              f"{registered[1]}; a typo accepted silently makes every later "
              f"refusal unexplained")
        failures += 1

    # ⚠️ CAPABILITY IS PRESENCE, and the number is the MODEL's. The stand-in
    # charges an implausible flat rate precisely so that an answer the
    # built-in pipeline could have produced proves the built-in pipeline
    # produced it.
    bound = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 10 and parts[0] == "BOUND":
            bound[parts[1]] = (int(parts[3]), int(parts[5]), int(parts[7]),
                               parts[9])
    for core in foreign:
        row = bound.get(core["name"])
        checks += 1
        if row is None or row[0] != 1:
            print(f"  FAIL {name}: core `{core['name']}` was refused after its "
                  f"model was registered; capability is presence, and the "
                  f"model is present")
            failures += 1
            continue
        checks += 1
        if row[2] != 4:
            print(f"  FAIL {name}: the model was handed {row[2]} of 4 retired "
                  f"instructions")
            failures += 1
        # ⚠️ And the machine SAYS whose number it is. A cycle count that
        # cannot name its author is the thing this boundary exists to
        # prevent, and in a stack mixing open and closed models it is the
        # only way a reader can tell one kind of claim from another.
        checks += 1
        if row[3] != core["model"]:
            print(f"  FAIL {name}: core `{core['name']}` is timed by "
                  f"`{core['model']}` and the machine attributes its cycle "
                  f"count to {row[3]!r}")
            failures += 1
        checks += 1
        if row[1] != 4000:
            print(f"  FAIL {name}: the model charges 1000 a piece for 4 "
                  f"instructions and the machine reported {row[1]}; a number "
                  f"this library could have produced means this library "
                  f"produced it")
            failures += 1

    checks += 1
    if kept != (1, 0):
        print(f"  FAIL {name}: selecting a core, then a core needing a foreign "
              f"model, gave {kept}; a refusal has to leave the machine on what "
              f"it was, not on a pipeline that answered in its place")
        failures += 1

    if not failures:
        print(f"  {name}: {len(cores)} machine(s) in {ir['schema']}; "
              f"{len(foreign)} name a model this library is not and are "
              f"refused, {sum(len(c['vendor']) for c in opaque)} opaque "
              f"parameter(s) carried verbatim, {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("a machine described openly, modelled privately: SKIP")
        return DECLINED
    print(f"a machine described openly, modelled privately: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
