#!/usr/bin/env python3
"""Generate examples/sve.axisl: SVE in Arm's encodings and Arm's semantics.

The corpus is generated because most of it is one form at four element sizes,
and a hand-copied family drifts. docs/scalable_vectors_design.md §10 stages it:
V1 the encodings and semantics, V2 the breadth, V3 the FFR, V4 floating point,
conversions, widening and gathers, V5 the SVE2 remainder. Run from the
repository root:

    tools/gen_sve.py examples/sve.axisl

`--check` compares instead of writing, so the ladder can hold the committed
corpus to its generator: an edit made to one alone is a failure.

    tools/gen_sve.py --check examples/sve.axisl
"""
import sys

VL = 128
VLB = VL // 8
SIZES = [("b", 8, 0), ("h", 16, 1), ("s", 32, 2), ("d", 64, 3)]
MIN = {8: "0x80", 16: "0x8000", 32: "0x80000000", 64: "0x8000000000000000"}
MAXU = {8: "0xff", 16: "0xffff", 32: "0xffffffff", 64: "0xffffffffffffffff"}

out = []
w = out.append


def ins(name, mnemonic, fmt, encoding, operands, asm, semantics, body, latency=1,
        rationale=None, category="simd"):
    w(f"  (definstruction {name}")
    w(f"    (mnemonic {mnemonic}) (isa sve) (category {category}) (format {fmt})")
    w(f"    (encoding {encoding})")
    w(f"    (operands {operands})")
    w(f'    (asm "{asm}")')
    w(f'    (semantics "{semantics}")')
    w(f"    {body}")
    w(f"    (latency {latency}) (throughput 1.0)")
    w("    (area-estimate-um2 1500.0) (power-estimate-mw 2.0) (expected-speedup 2.0)")
    w(f'    (rationale "{rationale or semantics}"))')
    w("")


def active(t, p="pg"):
    return f"(and vni{t} {p} 1)"


def flags(t, result, mask=None):
    """Arm's PredTest(mask, result): N first active true, Z none active true,
    C last active false, V clear -- as the i4 NZCV the A64 corpus keeps."""
    m = mask or "1"
    first = (f"(vredor vni{t} (and vni{t} (vmsof vni{t} {m}) {result}))" if mask
             else f"(vextract vni{t} {result} 0)")
    anyv = f"(vredor vni{t} {result})"
    last = f"(vlastb vni{t} {m} {result})"
    return (f"(setstate nzcv (or i4 (or i4 (select i4 (icmp_ne i{t} {first} 0) 8 0) "
            f"(select i4 (icmp_eq i{t} {anyv} 0) 4 0)) "
            f"(select i4 (icmp_eq i{t} {last} 0) 2 0)) i4)")


HEADER = f""";; SVE in Arm's own encodings and with Arm's semantics, at VL = {VL}.
;;
;; This corpus began as stage S7 of docs/scalable_vectors_design.md: an
;; illustrative SVE on an RV-style base, whose words were not Arm's and whose
;; shapes -- non-destructive predicated arithmetic, unpredicated compares, a
;; reduction into a general register, inactive lanes left unspecified -- were
;; what the S1-S6 mechanisms needed rather than what Arm defines. It is now
;; Arm's SVE and SVE2 (docs/scalable_vectors_design.md, V1-V6): every word is an A64 word
;; `llvm-mc` disassembles to the instruction named here, and
;; tools/sve_asl_check.py runs each one on Arm's ASL model and requires AXIS to
;; leave every X, Z, P, NZCV and byte of memory exactly as Arm does.
;;
;; What Arm's definition asked of the description, in one place:
;;   - A Z register is VL bits and a P register VL/8 bits, one per byte of Z.
;;     A predicate is held as one byte lane per bit, so at element size T a
;;     P lane holds T/8 bits and an element is active when its lowest is --
;;     Arm's rule. A predicate result writes 1 or 0, which sets that bit and
;;     clears the rest, as Arm does.
;;   - Predicated arithmetic is destructive (Zdn, Pg/M) and merges; compares,
;;     predicate logic and loads zero inactive elements (Pg/Z).
;;   - Compares and WHILELT set NZCV from Arm's PredTest: N the first active
;;     element, Z none active, C not the last active, V clear. That is a
;;     scalar computed over lanes and used beside a vector result, which is
;;     why a reduction may now sit inside a per-lane expression.
;;   - UADDV/SADDV accumulate at 64 bits (`vuaddv`/`vsaddv`); SMAXV and EORV
;;     at the element; each writes element 0 of Vd and zeroes the rest of Z.
;;   - WHILELT compares signed integers that do not wrap: element e is active
;;     while Xn + e < Xm, which is Xn < Xm and e < Xm - Xn as an unsigned
;;     64-bit difference.
;;   - Loads and stores address [Xn|SP, #imm, MUL VL]: imm is a signed four-bit
;;     count of vector lengths ({VLB} bytes here).
;;
;; Recorded limits, each named where it applies:
;;   - EXT is described at one immediate (#4, one .S element): its general
;;     form reads a byte offset chosen by the word, which the static permute
;;     operator cannot take.
;;   - LD2W's second register is Zt + 1 without Arm's wrap from Z31 to Z0.
;;   - The FFR is the fixed register p16, `(fixed 16)`: no word encodes it.
;;     First-fault and non-fault loads take "would fault" as "leaves the
;;     mem_lo/mem_hi window" -- the gate maps exactly that window as Normal
;;     memory, with an unmapped page after it -- so an MMU's other reasons to
;;     fault (permissions, attributes, a watchpoint) are not described.
;;   - An element suppressed by one of those loads keeps its old value, as
;;     Arm's model does.
;;   - Floating point is FPCR.DN = 1, round to nearest even, no flush to zero;
;;     FPSR's cumulative flags are not described.
;;   - FMAXV/FMINV/FMAXNMV/FMINNMV are described as what Arm's pairwise tree
;;     computes rather than as the tree, which the executors render
;;     exponentially (docs, V4).
;;   - Gathers and scatters are word and doubleword only.
;;   - SM4E/SM4EKEY, URSQRTE, the 128-bit PMULL forms and SVE2.1 are not
;;     described (docs, V6).
(axis-module sve
  (version "0.2.0")
  (target rvmt)
  (description "SVE in Arm's encodings: integer and bitwise arithmetic, shifts and immediates, INDEX, predication, compares and WHILE with NZCV, predicate construction and logic, reductions, permutes, loads and stores, the FFR with first-fault and non-fault loads, floating point and conversions, widening and narrowing, gathers and scatters, and SVE2's integer, shift and bitwise additions")

  (defisa sve
    (base armv8-a)
    (word-bits 64)
    (vector-bits {VL})
    (unspecified-realization compute)
    (registers "z[32]:i{VL}" "pc:i64" "nzcv:i4" "mem_lo:i64" "mem_hi:i64")
    (features simd scalable predicated custom)
    (memory-model armv8)
    (endianness little))

  ; Arm's layouts (Arm ARM, SVE), field for field; `encoding` pins each
  ; instruction's fixed bits.
  (defformat SVE_INT_UNPRED   ; ADD/SUB/MUL (vectors, unpredicated), TBL, permutes
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (zm 20 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_BIT_UNPRED   ; AND/ORR/EOR/BIC (vectors, unpredicated), .D only
    (bits 32)
    (fields (hi 31 24) (opc 23 22) (one 21) (zm 20 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_INT_PRED     ; binary arithmetic, predicated and destructive
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21) (opc 20 16) (op 15 13) (pg 12 10) (zm 9 5) (zd 4 0)))
  (defformat SVE_EXT          ; EXT, destructive, one immediate
    (bits 32)
    (fields (hi 31 21) (imm8h 20 16) (op 15 13) (imm8l 12 10) (zm 9 5) (zd 4 0)))
  (defformat SVE_DUP_R        ; DUP (scalar)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 10) (rn 9 5) (zd 4 0)))
  (defformat SVE_RED          ; reductions into a SIMD&FP register
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21) (opc 20 16) (op 15 13) (pg 12 10) (zn 9 5) (vd 4 0)))
  (defformat SVE_CMP          ; integer and float compares, vectors, Pg/Z
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21) (zm 20 16) (op 15 13) (pg 12 10) (zn 9 5) (ne 4) (pd 3 0)))
  (defformat SVE_WHILE        ; WHILELT, 64-bit operands
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (rm 20 16) (op 15 10) (rn 9 5) (eq 4) (pd 3 0)))
  (defformat SVE_PLOG         ; predicate logical, Pg/Z, and the flag-setting forms (s)
    (bits 32)
    (fields (hi 31 24) (op 23) (s 22) (zero 21 20) (pm 19 16) (op2 15 14) (pg 13 10) (o2 9) (pn 8 5) (o3 4) (pd 3 0)))
  (defformat SVE_PTRUE        ; PTRUE, by pattern
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 10) (pattern 9 5) (zero 4) (pd 3 0)))
  (defformat SVE_PFALSE
    (bits 32)
    (fields (hi 31 4) (pd 3 0)))
  (defformat SVE_PTEST
    (bits 32)
    (fields (hi 31 14) (pg 13 10) (zero 9) (pn 8 5) (lo 4 0)))
  (defformat SVE_INDEX_II     ; INDEX (immediates): step at 20:16, start at 9:5
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (step 20 16) (op 15 10) (start 9 5) (zd 4 0)))
  (defformat SVE_INDEX_RI     ; INDEX (scalar, immediate)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (step 20 16) (op 15 10) (rn 9 5) (zd 4 0)))
  (defformat SVE_INDEX_IR     ; INDEX (immediate, scalar)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (rm 20 16) (op 15 10) (start 9 5) (zd 4 0)))
  (defformat SVE_INDEX_RR     ; INDEX (scalars)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (rm 20 16) (op 15 10) (rn 9 5) (zd 4 0)))
  ; Shifts by immediate: tsz (bits 23:22 and 20:19) says the element size by
  ; its highest set bit, and the bits below it with imm3 are the amount.
  (defformat SVE_SHIFT_B
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (one 21) (tszl 20 19) (sh 18 16) (op 15 12) (opc 11 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_SHIFT_H
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (one 21) (tszl 20 20) (sh 19 16) (op 15 12) (opc 11 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_SHIFT_S
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (one 21) (sh 20 16) (op 15 12) (opc 11 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_SHIFT_D
    (bits 32)
    (fields (hi 31 24) (tszh 23 23) (sh 22 22 5 5) (one 21) (sh 20 16 4 0) (op 15 12) (opc 11 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_ADDI         ; ADD/SUB (immediate), destructive
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 19) (opc 18 16) (op2 15 14) (sh 13) (imm 12 5) (zd 4 0)))
  (defformat SVE_ADDI_B       ; the .B form, where sh must be clear
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 19) (opc 18 16) (op2 15 14) (sh 13) (imm 12 5) (zd 4 0)))
  (defformat SVE_BRK          ; BRKA/BRKB, Pg/Z
    (bits 32)
    (fields (hi 31 24) (b 23) (s 22) (op 21 14) (pg 13 10) (zero 9) (pn 8 5) (m 4) (pd 3 0)))
  (defformat SVE_LAST         ; LASTB (scalar)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 13) (pg 12 10) (zn 9 5) (rd 4 0)))
  (defformat SVE_CNTP
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 14) (pg 13 10) (zero 9) (pn 8 5) (rd 4 0)))
  (defformat SVE_LD_SI        ; contiguous load, scalar plus immediate
    (bits 32)
    (fields (hi 31 25) (dtype 24 21) (nf 20) (imm 19 16) (op 15 13) (pg 12 10) (rn 9 5) (zt 4 0)))
  (defformat SVE_ST_SI        ; contiguous store, scalar plus immediate
    (bits 32)
    (fields (hi 31 25) (msz 24 23) (size 22 21) (zero 20) (imm 19 16) (op 15 13) (pg 12 10) (rn 9 5) (zt 4 0)))
  (defformat SVE_LD2_SI       ; two-register structure load, scalar plus immediate
    (bits 32)
    (fields (hi 31 25) (msz 24 23) (num 22 21) (zero 20) (imm 19 16) (op 15 13) (pg 12 10) (rn 9 5) (zt 4 0)))
  (defformat SVE_F_UNPRED     ; FADD/FSUB/FMUL (vectors, unpredicated)
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21) (zm 20 16) (op 15 13) (opc 12 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_F_PRED       ; float arithmetic, predicated, destructive
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21 20) (opc 19 16) (op 15 13) (pg 12 10) (zm 9 5) (zd 4 0)))
  (defformat SVE_F_MLA        ; FMLA/FMLS/FNMLA/FNMLS
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (zm 20 16) (zero 15) (opc 14 13) (pg 12 10) (zn 9 5) (zda 4 0)))
  (defformat SVE_F_UNARY_INT  ; FABS/FNEG: in the integer unary group
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 19) (opc 18 16) (op2 15 13) (pg 12 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_F_UNARY      ; FSQRT, FRINT*
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 16) (op2 15 13) (pg 12 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_F_CMP0       ; float compares with #0.0
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 16) (op2 15 13) (pg 12 10) (zn 9 5) (o3 4) (pd 3 0)))
  (defformat SVE_F_RED        ; FADDV/FMAXV/... into Vd
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 16) (op2 15 13) (pg 12 10) (zn 9 5) (vd 4 0)))
  (defformat SVE_F_RED_A      ; FADDA Vdn, Pg, Vdn, Zm
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 16) (op2 15 13) (pg 12 10) (zm 9 5) (zd 4 0)))
  (defformat SVE_UNPK         ; SUNPKLO/HI, UUNPKLO/HI
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 18) (u 17) (h 16) (op2 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_WIDE        ; SVE2 widening and high-narrowing arithmetic
    (bits 32)
    (fields (hi 31 24) (size 23 22) (zero 21) (zm 20 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_XTN         ; SQXTN/UQXTN/SQXTUN, bottom and top
    (bits 32)
    (fields (hi 31 23) (tszh 22) (one 21) (tszl 20 19) (zero 18 16) (op 15 13) (opc 12 11) (t 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_GATHER       ; gathers and scatters, [Xn, Zm, ...]
    (bits 32)
    (fields (hi 31 21) (zm 20 16) (op 15 13) (pg 12 10) (rn 9 5) (zt 4 0)))
  (defformat SVE_GATHER_I     ; gathers and scatters, [Zn, #imm]
    (bits 32)
    (fields (hi 31 21) (imm 20 16) (op 15 13) (pg 12 10) (zn 9 5) (zt 4 0)))
  (defformat SVE_PSHIFT_B     ; predicated shifts by immediate, .B
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (op 21 16) (op2 15 13) (pg 12 10) (tszl 9 8) (sh 7 5) (zd 4 0)))
  (defformat SVE_PSHIFT_H
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (op 21 16) (op2 15 13) (pg 12 10) (tszl 9 9) (sh 8 5) (zd 4 0)))
  (defformat SVE_PSHIFT_S
    (bits 32)
    (fields (hi 31 24) (tszh 23 22) (op 21 16) (op2 15 13) (pg 12 10) (sh 9 5) (zd 4 0)))
  (defformat SVE_PSHIFT_D
    (bits 32)
    (fields (hi 31 24) (tszh 23 23) (sh 22 22 5 5) (op 21 16) (op2 15 13) (pg 12 10) (sh 9 5 4 0) (zd 4 0)))
  (defformat SVE2_SHN_H       ; SSHLL and narrowing shifts, .H wide (.B narrow)
    (bits 32)
    (fields (hi 31 23) (tszh 22) (zero 21) (tszl 20 19) (sh 18 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_SHN_S
    (bits 32)
    (fields (hi 31 23) (tszh 22) (zero 21) (tszl 20 20) (sh 19 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_SHN_D
    (bits 32)
    (fields (hi 31 23) (tszh 22) (zero 21) (sh 20 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_TERN        ; EOR3/BCAX/BSL/BSL1N/BSL2N/NBSL
    (bits 32)
    (fields (hi 31 24) (opc 23 22) (one 21) (zm 20 16) (op 15 10) (zk 9 5) (zd 4 0)))
  (defformat SVE2_CADD        ; CADD/SQCADD
    (bits 32)
    (fields (hi 31 24) (size 23 22) (op 21 16) (op2 15 10) (zm 9 5) (zd 4 0)))
  (defformat SVE2_MATCH       ; MATCH/NMATCH
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (zm 20 16) (op 15 13) (pg 12 10) (zn 9 5) (o 4) (pd 3 0)))
  (defformat SVE2_HIST        ; HISTCNT
    (bits 32)
    (fields (hi 31 24) (size 23 22) (one 21) (zm 20 16) (op 15 13) (pg 12 10) (zn 9 5) (zd 4 0)))
  (defformat SVE2_CRYPTO      ; AESE/AESD (and SM4E)
    (bits 32)
    (fields (hi 31 21) (op 20 16) (op2 15 10) (zm 9 5) (zd 4 0)))
  (defformat SVE2_CRYPTO_U    ; AESMC/AESIMC
    (bits 32)
    (fields (hi 31 21) (op 20 16) (op2 15 10) (zero 9 5) (zd 4 0)))
  (defformat SVE2_RAX         ; RAX1
    (bits 32)
    (fields (hi 31 21) (zm 20 16) (op 15 10) (zn 9 5) (zd 4 0)))
  (defformat SVE_FFR0         ; SETFFR: no operand the word encodes
    (bits 32)
    (fields (hi 31 0)))
  (defformat SVE_FFR_N        ; WRFFR Pn
    (bits 32)
    (fields (hi 31 9) (pn 8 5) (lo 4 0)))
  (defformat SVE_FFR_D        ; RDFFR Pd (unpredicated)
    (bits 32)
    (fields (hi 31 4) (pd 3 0)))
  (defformat SVE_FFR_GD       ; RDFFR(S) Pd, Pg/Z
    (bits 32)
    (fields (hi 31 9) (pg 8 5) (zero 4) (pd 3 0)))
  (defformat SVE_LD_SS        ; contiguous load, scalar plus scalar
    (bits 32)
    (fields (hi 31 25) (dtype 24 21) (rm 20 16) (op 15 13) (pg 12 10) (rn 9 5) (zt 4 0)))
"""
w(HEADER)

# ---- unpredicated integer ----------------------------------------------------
w("  ; --- unpredicated integer and bitwise arithmetic -----------------------")
for op, opc, sem, name in (("add", 0, "add", "Add"), ("sub", 1, "sub", "Subtract")):
    for s, t, sz in SIZES:
        ins(f"{op}_z_{s}", f"{op.upper()}_Z_{s.upper()}", "SVE_INT_UNPRED",
            f"(hi 4) (size {sz}) (one 1) (op {opc})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_z_{s} $zd, $zn, $zm", f"{name} over {t}-bit elements",
            f"(formal ({sem} vni{t} zn zm))")
for s, t, sz in SIZES:
    ins(f"mul_z_{s}", f"MUL_Z_{s.upper()}", "SVE_INT_UNPRED",
        f"(hi 4) (size {sz}) (one 1) (op 24)",
        f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)",
        f"mul_z_{s} $zd, $zn, $zm", f"Multiply {t}-bit elements, low half (SVE2)",
        f"(formal (mul vni{t} zn zm))", latency=4)
for op, opc, sem in (("and", 0, "(and vni64 zn zm)"), ("orr", 1, "(or vni64 zn zm)"),
                     ("eor", 2, "(xor vni64 zn zm)"),
                     ("bic", 3, "(and vni64 zn (xor vni64 zm 0xffffffffffffffff))")):
    ins(f"{op}_z_d", f"{op.upper()}_Z_D", "SVE_BIT_UNPRED",
        f"(hi 4) (opc {opc}) (one 1) (op 12)",
        "(zd vreg i64 out) (zn vreg i64 in) (zm vreg i64 in)",
        f"{op}_z_d $zd, $zn, $zm",
        f"Bitwise {op.upper()}: one instruction whatever the element size, written at .D",
        f"(formal {sem})")

# ---- predicated, destructive -------------------------------------------------
w("  ; --- predicated and destructive: Zdn = Pg ? Zdn op Zm : Zdn -------------")
PRED = [("add_m", "ADD_M", 0, "add", "Add"), ("sub_m", "SUB_M", 1, "sub", "Subtract"),
        ("smax_m", "SMAX_M", 8, "max", "Signed maximum"), ("umax_m", "UMAX_M", 9, "maxu", "Unsigned maximum"),
        ("smin_m", "SMIN_M", 10, "min", "Signed minimum"), ("umin_m", "UMIN_M", 11, "minu", "Unsigned minimum")]
for base, mn, opc, sem, name in PRED:
    for s, t, sz in SIZES:
        ins(f"{base}_{s}", f"{mn}_{s.upper()}", "SVE_INT_PRED",
            f"(hi 4) (size {sz}) (zero 0) (opc {opc}) (op 0)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)",
            f"{base}_{s} $zd, $pg, $zm",
            f"{name} of active {t}-bit elements into Zdn; inactive ones keep their value",
            f"(formal (vmerge vni{t} {active(t)} ({sem} vni{t} zd zm) zd))")

# ---- permutes ----------------------------------------------------------------
w("  ; --- permutes, at every element size ----------------------------------------")
for s, t, sz in SIZES:
    ins(f"tbl_z_{s}", f"TBL_Z_{s.upper()}", "SVE_INT_UNPRED", f"(hi 5) (size {sz}) (one 1) (op 12)",
        f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"tbl_z_{s} $zd, $zn, $zm",
        f"Table lookup over {t}-bit elements: element i reads zn[zm[i]], or zero when that index is out of range",
        f"(formal (vrgather vni{t} zn zm))", latency=2,
        rationale="The dynamic permute: a select over every source lane")
for op, code in (("zip1", 24), ("zip2", 25), ("uzp1", 26), ("uzp2", 27), ("trn1", 28), ("trn2", 29)):
    for s, t, sz in SIZES:
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_INT_UNPRED", f"(hi 5) (size {sz}) (one 1) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()} over {t}-bit elements", f"(formal (v{op} vni{t} zn zm))")
ins("ext_s", "EXT_S", "SVE_EXT", "(hi 41) (imm8h 0) (op 0) (imm8l 4)",
    "(zd vreg i32 out) (zdn vreg i32 in (derive zd 0)) (zm vreg i32 in)", "ext_s $zd, $zm",
    "EXT #4: the vector pair Zm:Zdn shifted down by one 32-bit element",
    "(formal (vext vni32 zdn zm 1))",
    rationale="Destructive, as Arm's EXT is -- its source is the destination's own register, "
              "read as a separate operand because lane k reads element k+1 of it; described at "
              "the one immediate a static permute can take")
for s, t, sz in SIZES:
    reg = "a64_gpr64sp i64" if t == 64 else "a64_gpr32sp i32"
    ins(f"dup_{s}", f"DUP_{s.upper()}", "SVE_DUP_R", f"(hi 5) (size {sz}) (op 2062)",
        f"(zd vreg i{t} out) (rn {reg} in)", f"dup_{s} $zd, $rn",
        f"Broadcast the low {t} bits of {'Xn|SP' if t == 64 else 'Wn|WSP'} to every element",
        f"(formal (vdup vni{t} rn))")
w("  ; --- INDEX: element e is start + e * step, at the element width ------------")
def scalar_src(t, name, imm):
    if imm:
        return f"(sext i{t} 5 {name})"
    return name if t in (32, 64) else f"(and i32 {name} {MAXU[t]})"
for form, code, fmt, a, b in (("ii", 16, "SVE_INDEX_II", "start", "step"),
                              ("ri", 17, "SVE_INDEX_RI", "rn", "step"),
                              ("ir", 18, "SVE_INDEX_IR", "start", "rm"),
                              ("rr", 19, "SVE_INDEX_RR", "rn", "rm")):
    for s, t, sz in SIZES:
        reg = "a64_gpr64 i64" if t == 64 else "a64_gpr32 i32"
        ops = [f"(zd vreg i{t} out)"]
        ops.append(f"({a} {reg} in)" if a == "rn" else f"({a} imm i5 in)")
        ops.append(f"({b} {reg} in)" if b == "rm" else f"({b} imm i5 in)")
        start_v = scalar_src(t, a, a == "start")
        step_v = scalar_src(t, b, b == "step")
        ins(f"index_{form}_{s}", f"INDEX_{form.upper()}_{s.upper()}", fmt,
            f"(hi 4) (size {sz}) (one 1) (op {code})", " ".join(ops),
            f"index_{form}_{s} $zd, ${a}, ${b}",
            f"INDEX over {t}-bit elements: element e is {a} + e * {b}, wrapping at the element",
            f"(formal (add vni{t} (vdup vni{t} {start_v}) (mul vni{t} (vid vni{t}) (vdup vni{t} {step_v}))))")

# ---- reductions ----------------------------------------------------------------
w("  ; --- reductions: into element 0 of Vd, the rest of Z zeroed ---------------")
def lane0(t, value, vt=None):
    vt = vt or t
    return (f"(formal (vmerge vni{vt} (icmp_eq vni{vt} (vid vni{vt}) (vdup vni{vt} 0)) "
            f"(vdup vni{vt} {value}) 0))")
for s, t, sz in SIZES:
    ins(f"uaddv_{s}", f"UADDV_{s.upper()}", "SVE_RED", f"(hi 4) (size {sz}) (zero 0) (opc 1) (op 1)",
        f"(vd vreg i64 out) (pg preg i{t} in) (zn vreg i{t} in)", f"uaddv_{s} $vd, $pg, $zn",
        f"Unsigned sum of the active {t}-bit elements, at 64 bits, into Dd",
        lane0(t, f"(vuaddv vni{t} (vmerge vni{t} {active(t)} zn 0))", 64), latency=4)
    if t != 64:
        ins(f"saddv_{s}", f"SADDV_{s.upper()}", "SVE_RED", f"(hi 4) (size {sz}) (zero 0) (opc 0) (op 1)",
            f"(vd vreg i64 out) (pg preg i{t} in) (zn vreg i{t} in)", f"saddv_{s} $vd, $pg, $zn",
            f"Signed sum of the active {t}-bit elements, at 64 bits, into Dd",
            lane0(t, f"(vsaddv vni{t} (vmerge vni{t} {active(t)} zn 0))", 64), latency=4)
MAXS = {8: "0x7f", 16: "0x7fff", 32: "0x7fffffff", 64: "0x7fffffffffffffff"}
for name, opc, red, ident, what in (("smaxv", 8, "vredmax", MIN, "signed maximum"),
                                    ("umaxv", 9, "vredmaxu", {t: "0" for t in MIN}, "unsigned maximum"),
                                    ("sminv", 10, "vredmin", MAXS, "signed minimum"),
                                    ("uminv", 11, "vredminu", MAXU, "unsigned minimum"),
                                    ("orv", 24, "vredor", {t: "0" for t in MIN}, "OR"),
                                    ("eorv", 25, "vredxor", {t: "0" for t in MIN}, "exclusive OR"),
                                    ("andv", 26, "vredand", MAXU, "AND")):
    for s, t, sz in SIZES:
        ins(f"{name}_{s}", f"{name.upper()}_{s.upper()}", "SVE_RED",
            f"(hi 4) (size {sz}) (zero 0) (opc {opc}) (op 1)",
            f"(vd vreg i{t} out) (pg preg i{t} in) (zn vreg i{t} in)", f"{name}_{s} $vd, $pg, $zn",
            f"The {what} of the active {t}-bit elements, or its identity {ident[t]} when none is",
            lane0(t, f"({red} vni{t} (vmerge vni{t} {active(t)} zn {ident[t]}))"), latency=4)

# ---- compares and WHILE, with NZCV --------------------------------------------
w("  ; --- compares and WHILE: a predicate, and NZCV from Arm's PredTest --------")
CMPS = (("cmpge", 4, 0, "(icmp_sge vni{t} zn zm)"), ("cmpgt", 4, 1, "(icmp_slt vni{t} zm zn)"),
        ("cmphs", 0, 0, "(icmp_uge vni{t} zn zm)"), ("cmphi", 0, 1, "(icmp_ult vni{t} zm zn)"),
        ("cmpeq", 5, 0, "(icmp_eq vni{t} zn zm)"), ("cmpne", 5, 1, "(icmp_ne vni{t} zn zm)"))
for op, code, ne, cmp in CMPS:
    for s, t, sz in SIZES:
        result = f"(and vni{t} {active(t)} {cmp.format(t=t)})"
        ins(f"{op}_p_{s}", f"{op.upper()}_P_{s.upper()}", "SVE_CMP",
            f"(hi 36) (size {sz}) (zero 0) (op {code}) (ne {ne})",
            f"(pd preg i{t} out) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_p_{s} $pd, $pg, $zn, $zm",
            f"{op.upper()} of active {t}-bit elements, inactive zero; NZCV from the result",
            f"(behavior (set pd {result}) {flags(t, result, active(t))})")
# Element e is active while Xn + e compares with Xm, the integers not wrapping.
# `<` is `a < b and e < b - a`; `<=` is `a <= b and e <= b - a` -- the unsigned
# 64-bit difference is exact whenever the first half holds.
WHILES = (("whilelt", 5, 0, "(icmp_slt i64 rn rm)", "(icmp_ult i64 E D)", "signed, <"),
          ("whilele", 5, 1, "(icmp_sge i64 rm rn)", "(icmp_uge i64 D E)", "signed, <="),
          ("whilelo", 7, 0, "(icmp_ult i64 rn rm)", "(icmp_ult i64 E D)", "unsigned, <"),
          ("whilels", 7, 1, "(icmp_uge i64 rm rn)", "(icmp_uge i64 D E)", "unsigned, <="))
for op, code, eq, first, lane, what in WHILES:
    for s, t, sz in SIZES:
        e = f"(zext i64 {t} (vid vni{t}))"
        d = f"(vdup vni{t} (sub i64 rm rn))"
        result = (f"(vmerge vni{t} (and i64 (vdup vni{t} {first}) "
                  f"{lane.replace('E', e).replace('D', d)}) 1 0)")
        ins(f"{op}_p_{s}", f"{op.upper()}_P_{s.upper()}", "SVE_WHILE",
            f"(hi 37) (size {sz}) (one 1) (op {code}) (eq {eq})",
            f"(pd preg i{t} out) (rn a64_gpr64 i64 in) (rm a64_gpr64 i64 in)",
            f"{op}_p_{s} $pd, $rn, $rm",
            f"Element e is active while Xn + e against Xm holds ({what}), without wrapping; NZCV from the result",
            f"(behavior (set pd {result}) {flags(t, result)})")

# ---- predicate construction and test --------------------------------------------
w("  ; --- PTRUE, PFALSE, PTEST ---------------------------------------------------")
def pattern_count(n):
    """PTRUE's element count for each pattern at `n` elements, as a select chain."""
    def count(p):
        if p == 0:
            return 1 << (n.bit_length() - 1)
        if 1 <= p <= 8:
            return p if p <= n else 0
        if 9 <= p <= 13:
            k = 16 << (p - 9)
            return k if k <= n else 0
        return {29: n - n % 4, 30: n - n % 3, 31: n}.get(p, 0)
    tree = "0"
    for p in range(32):
        c = count(p)
        if c:
            tree = f"(select i64 (icmp_eq i64 (zext i64 5 pattern) {p}) {c} {tree})"
    return tree
for s, t, sz in SIZES:
    n = VL // t
    ins(f"ptrue_{s}", f"PTRUE_{s.upper()}", "SVE_PTRUE", f"(hi 37) (size {sz}) (op 1592) (zero 0)",
        f"(pd preg i{t} out) (pattern imm i5 in)", f"ptrue_{s} $pd, $pattern",
        f"The first N {t}-bit elements active, N the pattern's count at VL = {VL}; the rest inactive",
        f"(formal (vmerge vni{t} (icmp_ult i64 (zext i64 {t} (vid vni{t})) (vdup vni{t} {pattern_count(n)})) 1 0))")
ins("pfalse", "PFALSE", "SVE_PFALSE", "(hi 38899264)", "(pd preg i8 out)", "pfalse $pd",
    "Every predicate bit clear", "(formal (vdup vni8 0))")
ptest = "(and vni8 (and vni8 pg 1) (and vni8 pn 1))"
ins("ptest", "PTEST", "SVE_PTEST", "(hi 38211) (zero 0) (lo 0)", "(pg preg i8 in) (pn preg i8 in)",
    "ptest $pg, $pn", "NZCV from Pn under Pg, Arm's PredTest; nothing else changes",
    f"(behavior {flags(8, ptest, active(8))})")

# ---- predicate logic, breaks, LASTA/LASTB, CNTP -------------------------------
w("  ; --- predicate logic, breaks, LASTA/LASTB, CNTP ---------------------------")
# (bit 23, o2, o3) and what a bit of the result is, before Pg zeroes it.
PLOG = (("and", 0, 0, 0, "(and vni8 pn pm)"), ("bic", 0, 0, 1, "(and vni8 pn (xor vni8 pm 1))"),
        ("eor", 0, 1, 0, "(xor vni8 pn pm)"), ("orr", 1, 0, 0, "(or vni8 pn pm)"),
        ("orn", 1, 0, 1, "(or vni8 pn (xor vni8 pm 1))"), ("nor", 1, 1, 0, "(xor vni8 (or vni8 pn pm) 1)"),
        ("nand", 1, 1, 1, "(xor vni8 (and vni8 pn pm) 1)"))
for op, b23, o2, o3, value in PLOG:
    result = f"(and vni8 pg {value})"
    for flagged in (0, 1):
        name = f"{op}s_p" if flagged else f"{op}_p"
        body = (f"(behavior (set pd {result}) {flags(8, result, active(8))})" if flagged
                else f"(formal {result})")
        ins(name, name.upper(), "SVE_PLOG", f"(hi 37) (op {b23}) (s {flagged}) (zero 0) (op2 1) (o2 {o2}) (o3 {o3})",
            "(pd preg i8 out) (pg preg i8 in) (pn preg i8 in) (pm preg i8 in)",
            f"{name} $pd, $pg, $pn, $pm",
            f"Predicate {op.upper()} under Pg, inactive zero" + ("; NZCV from the result" if flagged else ""),
            body)
ins("sel_p", "SEL_P", "SVE_PLOG", "(hi 37) (op 0) (s 0) (zero 0) (op2 1) (o2 1) (o3 1)",
    "(pd preg i8 out) (pg preg i8 in) (pn preg i8 in) (pm preg i8 in)", "sel_p $pd, $pg, $pn, $pm",
    "Pn where Pg is active, Pm where it is not", "(formal (vmerge vni8 (and vni8 pg 1) pn pm))")
for op, b, fn, desc in (("brka", 0, "vmsif", "up to and including"), ("brkb", 1, "vmsbf", "before")):
    result = f"(and vni8 (and vni8 pg 1) ({fn} vni8 (and vni8 (and vni8 pg 1) (and vni8 pn 1))))"
    for flagged in (0, 1):
        name = f"{op}s_p" if flagged else f"{op}_p"
        body = (f"(behavior (set pd {result}) {flags(8, result, active(8))})" if flagged
                else f"(formal {result})")
        ins(name, name.upper(), "SVE_BRK", f"(hi 37) (b {b}) (s {flagged}) (op 65) (zero 0) (m 0)",
            "(pd preg i8 out) (pg preg i8 in) (pn preg i8 in)", f"{name} $pd, $pg, $pn",
            f"Active elements {desc} the first active true element of Pn; the rest zero"
            + ("; NZCV from the result" if flagged else ""), body)
for op, code, fn in (("lasta", 261, "vlasta"), ("lastb", 269, "vlastb")):
    for s, t, sz in SIZES:
        reg = "a64_gpr64 i64" if t == 64 else "a64_gpr32 i32"
        value = f"({fn} vni{t} {active(t)} zn)"
        if t < 32:
            value = f"(zext i32 {t} {value})"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_LAST", f"(hi 5) (size {sz}) (op {code})",
            f"(rd {reg} out) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $rd, $pg, $zn",
            ("The element after the last active one, wrapping, or element 0 when none is active"
             if op == "lasta" else "The last active element, or the last element when none is active"),
            f"(formal {value})", latency=3)
for s, t, sz in SIZES:
    ins(f"cntp_{s}", f"CNTP_{s.upper()}", "SVE_CNTP", f"(hi 37) (size {sz}) (op 130) (zero 0)",
        f"(rd a64_gpr64 i64 out) (pg preg i{t} in) (pn preg i{t} in)", f"cntp_{s} $rd, $pg, $pn",
        f"How many {t}-bit elements are active in both Pg and Pn",
        f"(formal (zext i64 {t} (vcpop vni{t} (and vni{t} {active(t)} {active(t, 'pn')}))))", latency=2)

# ---- shifts and immediates ---------------------------------------------------------
w("  ; --- shifts by immediate, unpredicated: tsz:imm3 says the size and the amount")
# A left shift by the field's low bits; a right shift by esize minus them, from
# 1 to esize -- a whole-element shift is expressed without shifting that far.
for s, t, sz in SIZES:
    fmt = f"SVE_SHIFT_{s.upper()}"
    enc = {8: "(tszh 0) (tszl 1)", 16: "(tszh 0) (tszl 1)", 32: "(tszh 1)", 64: "(tszh 1)"}[t]
    bits = {8: 3, 16: 4, 32: 5, 64: 6}[t]
    amount = f"(zext i{t} {bits} sh)" if t > bits else "sh"
    for op, opc in (("lsl", 3), ("lsr", 1), ("asr", 0)):
        if op == "lsl":
            value = f"(shl vni{t} zn (vdup vni{t} {amount}))"
        else:
            right = f"(sub i{t} {t} {amount})"
            whole = "(vdup vni{t} 0)".format(t=t) if op == "lsr" else f"(ashr vni{t} zn (vdup vni{t} {t - 1}))"
            shift = "lshr" if op == "lsr" else "ashr"
            value = (f"(vmerge vni{t} (vdup vni{t} (icmp_eq i{t} {amount} 0)) {whole} "
                     f"({shift} vni{t} zn (vdup vni{t} {right})))")
        ins(f"{op}_i_{s}", f"{op.upper()}_I_{s.upper()}", fmt, f"(hi 4) {enc} (one 1) (op 9) (opc {opc})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (sh imm i{bits} in)", f"{op}_i_{s} $zd, $zn, $sh",
            f"{op.upper()} of {t}-bit elements by an immediate"
            + (" (0 to esize-1)" if op == "lsl" else " (1 to esize: esize minus the field)"),
            f"(formal {value})")
w("  ; --- shifts by vector, predicated and destructive ----------------------------")
for op, opc in (("asr", 16), ("lsr", 17), ("lsl", 19)):
    for s, t, sz in SIZES:
        far = f"(icmp_uge vni{t} zm (vdup vni{t} {t}))"
        near = {"lsl": f"(shl vni{t} zd zm)", "lsr": f"(lshr vni{t} zd zm)", "asr": f"(ashr vni{t} zd zm)"}[op]
        over = f"(ashr vni{t} zd (vdup vni{t} {t - 1}))" if op == "asr" else "0"
        ins(f"{op}_m_{s}", f"{op.upper()}_M_{s.upper()}", "SVE_INT_PRED",
            f"(hi 4) (size {sz}) (zero 0) (opc {opc}) (op 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"{op}_m_{s} $zd, $pg, $zm",
            f"{op.upper()} of active {t}-bit elements by the matching element of Zm, as an unsigned "
            f"amount; esize or more shifts every bit out",
            f"(formal (vmerge vni{t} {active(t)} (vmerge vni{t} {far} {over} {near}) zd))")
w("  ; --- ADD/SUB (immediate): Zdn +- imm8, shifted left by 8 when sh is set --")
for op, opc in (("add", 0), ("sub", 1)):
    for s, t, sz in SIZES:
        if t == 8:
            fmt, enc, ops, imm = "SVE_ADDI_B", f"(hi 37) (size 0) (op 4) (opc {opc}) (op2 3) (sh 0)", \
                "(zd vreg i8 inout) (imm imm i8 in)", "imm"
        else:
            fmt, enc = "SVE_ADDI", f"(hi 37) (size {sz}) (op 4) (opc {opc}) (op2 3)"
            ops = f"(zd vreg i{t} inout) (imm imm i8 in) (sh imm i1 in)"
            imm = f"(shl i{t} (zext i{t} 8 imm) (mul i{t} (zext i{t} 1 sh) 8))"
        ins(f"{op}_i_{s}", f"{op.upper()}_I_{s.upper()}", fmt, enc, ops,
            f"{op}_i_{s} $zd, $imm" + ("" if t == 8 else ", $sh"),
            f"{op.upper()} an unsigned immediate to every {t}-bit element of Zdn",
            f"(formal ({op} vni{t} zd (vdup vni{t} {imm})))")

# ---- memory ------------------------------------------------------------------------
w("  ; --- loads and stores: [Xn|SP, #imm, MUL VL], Pg/Z loads -----------------")
def base(scale=1):
    mul = VLB * scale
    return f"(add i64 rn (mul i64 (sext i64 4 imm) {mul}))"
LD = {"b": (0, 0, 0), "h": (5, 1, 1), "s": (10, 2, 2), "d": (15, 3, 3)}
for s, t, sz in SIZES:
    dtype, msz, size = LD[s]
    ins(f"ld1_{s}", f"LD1_{s.upper()}", "SVE_LD_SI", f"(hi 82) (dtype {dtype}) (nf 0) (op 5)",
        f"(zt vreg i{t} out) (pg preg i{t} in) (rn a64_gpr64sp i64 in) (imm imm i4 in)",
        f"ld1_{s} $zt, $pg, $rn, $imm",
        f"LD1{'BHWD'['bhsd'.index(s)]}: active {t}-bit elements from [Xn + imm * VL], inactive zero",
        f"(behavior (when (ne {active(t)} 0) (set zt (vload vni{t} {base()}))) "
        f"(when (eq {active(t)} 0) (set zt 0)))", latency=4, category="custom")
    ins(f"st1_{s}", f"ST1_{s.upper()}", "SVE_ST_SI", f"(hi 114) (msz {msz}) (size {size}) (zero 0) (op 7)",
        f"(zt vreg i{t} in) (pg preg i{t} in) (rn a64_gpr64sp i64 in) (imm imm i4 in)",
        f"st1_{s} $zt, $pg, $rn, $imm",
        f"ST1{'BHWD'['bhsd'.index(s)]}: active {t}-bit elements to [Xn + imm * VL], no others",
        f"(behavior (when (ne {active(t)} 0) (store (vaddr vni{t} {base()}) zt i{t})))",
        latency=4, category="custom")
ins("ld2_s", "LD2_S", "SVE_LD2_SI", "(hi 82) (msz 2) (num 1) (zero 0) (op 7)",
    "(zt vreg i32 out) (zt2 vreg i32 out (derive zt 1)) (pg preg i32 in) (rn a64_gpr64sp i64 in) (imm imm i4 in)",
    "ld2_s $zt, $pg, $rn, $imm",
    "LD2W: two-field structures from [Xn + 2 * imm * VL] into Zt and Zt+1, inactive zero",
    f"(behavior (when (ne {active(32)} 0) (set zt (vload_seg vni32 2 0 {base(2)}))) "
    f"(when (ne {active(32)} 0) (set zt2 (vload_seg vni32 2 1 {base(2)}))) "
    f"(when (eq {active(32)} 0) (set zt 0)) (when (eq {active(32)} 0) (set zt2 0)))", latency=4, category="custom")
# ---- floating point (V4a) ------------------------------------------------------
# FPCR as the gate runs it: DN = 1 (the default NaN for every NaN result, as the
# AArch64 corpus describes), round to nearest even, no flush to zero. FPSR's
# cumulative flags are not part of what is compared.
#
# FMAX/FMIN/FMAXNM/FMINNM and FRINT* are the AArch64 corpus's own `defsem`s,
# copied in verbatim at generation time: their NaN and signed-zero rules are
# the subtle part, and one statement of them is checked against Arm twice
# rather than two statements once each.
FSIZES = [("h", 16, 1), ("s", 32, 2), ("d", 64, 3)]
SIGN = {16: "0x8000", 32: "0x80000000", 64: "0x8000000000000000"}
NOSIGN = {16: "0x7fff", 32: "0x7fffffff", 64: "0x7fffffffffffffff"}
DNAN = {16: "0x7e00", 32: "0x7fc00000", 64: "0x7ff8000000000000"}
PINF = {16: "0x7c00", 32: "0x7f800000", 64: "0x7ff0000000000000"}
NINF = {16: "0xfc00", 32: "0xff800000", 64: "0xfff0000000000000"}
NZERO = SIGN

def defsems(names):
    import pathlib
    text = (pathlib.Path(__file__).resolve().parent.parent
            / "examples" / "aarch64_translation_seed.axisl").read_text()
    out = []
    for name in names:
        at = text.index(f"(defsem {name} ")
        depth, end = 0, at
        for end in range(at, len(text)):
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            if depth == 0:
                break
        out.append("  " + text[at:end + 1])
    return out

w("  ; --- floating point: Arm's FMAX/FMIN/FRINT rules, shared with the A64 corpus")
for line in defsems([f"a64_{op}_{t}" for t in (16, 32, 64)
                     for op in ("fmax", "fmin", "fmaxnm", "fminnm",
                                "frintn", "frintp", "frintm", "frintz", "frinta")]):
    w(line)
w("")

w("  ; --- FADD/FSUB/FMUL (vectors, unpredicated) --------------------------------")
for op, opc in (("fadd", 0), ("fsub", 1), ("fmul", 2)):
    for s, t, sz in FSIZES:
        ins(f"{op}_z_{s}", f"{op.upper()}_Z_{s.upper()}", "SVE_F_UNPRED",
            f"(hi 101) (size {sz}) (zero 0) (op 0) (opc {opc})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_z_{s} $zd, $zn, $zm",
            f"{op.upper()} of every {t}-bit float element", f"(formal ({op} vnf{t} zn zm))", latency=3)

def fminmax(op, t, a, b):
    return f"(vmap vni{t} ((a {a}) (b {b})) (a64_{op}_{t} a b))"

FPRED = (("fadd", 0, lambda t: f"(fadd vnf{t} zd zm)"),
         ("fsub", 1, lambda t: f"(fsub vnf{t} zd zm)"),
         ("fmul", 2, lambda t: f"(fmul vnf{t} zd zm)"),
         ("fsubr", 3, lambda t: f"(fsub vnf{t} zm zd)"),
         ("fmaxnm", 4, lambda t: fminmax("fmaxnm", t, "zd", "zm")),
         ("fminnm", 5, lambda t: fminmax("fminnm", t, "zd", "zm")),
         ("fmax", 6, lambda t: fminmax("fmax", t, "zd", "zm")),
         ("fmin", 7, lambda t: fminmax("fmin", t, "zd", "zm")),
         ("fabd", 8, lambda t: f"(and vni{t} (fsub vnf{t} zd zm) {NOSIGN[t]})"),
         ("fdivr", 12, lambda t: f"(fdiv vnf{t} zm zd)"),
         ("fdiv", 13, lambda t: f"(fdiv vnf{t} zd zm)"))
w("  ; --- predicated, destructive: Zdn = Zdn op Zm where active --------------------")
for op, opc, value in FPRED:
    for s, t, sz in FSIZES:
        ins(f"{op}_m_{s}", f"{op.upper()}_M_{s.upper()}", "SVE_F_PRED",
            f"(hi 101) (size {sz}) (zero 0) (opc {opc}) (op 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"{op}_m_{s} $zd, $pg, $zm",
            f"{op.upper()} of active {t}-bit float elements into Zdn; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value(t)} zd))", latency=4)

w("  ; --- FMLA/FMLS/FNMLA/FNMLS: fused, Zda accumulates where active -----------")
neg = lambda t, x: f"(xor vni{t} {x} {SIGN[t]})"
FMLA = (("fmla", 0, lambda t: f"(fma vnf{t} zn zm zda)"),
        ("fmls", 1, lambda t: f"(fma vnf{t} {neg(t, 'zn')} zm zda)"),
        ("fnmla", 2, lambda t: f"(fma vnf{t} {neg(t, 'zn')} zm {neg(t, 'zda')})"),
        ("fnmls", 3, lambda t: f"(fma vnf{t} zn zm {neg(t, 'zda')})"))
for op, opc, value in FMLA:
    for s, t, sz in FSIZES:
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_MLA",
            f"(hi 101) (size {sz}) (one 1) (zero 0) (opc {opc})",
            f"(zda vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $zda, $pg, $zn, $zm",
            f"{op.upper()}: fused multiply-add of {t}-bit floats, negating as Arm's names say, "
            f"into Zda where active", f"(formal (vmerge vni{t} {active(t)} {value(t)} zda))", latency=4)

w("  ; --- FABS/FNEG, FSQRT, FRINT*: unary, merging --------------------------------")
for op, opc, value in (("fabs", 4, lambda t: f"(and vni{t} zn {NOSIGN[t]})"),
                       ("fneg", 5, lambda t: neg(t, "zn"))):
    for s, t, sz in FSIZES:
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_UNARY_INT",
            f"(hi 4) (size {sz}) (op 3) (opc {opc}) (op2 5)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $zd, $pg, $zn",
            f"{op.upper()} of active {t}-bit float elements: the sign bit alone, NaN or not",
            f"(formal (vmerge vni{t} {active(t)} {value(t)} zd))")
UNARY = [("fsqrt", 13, lambda t: f"(fsqrt vnf{t} zn)", 12)] + [
    (f"frint{r}", code, (lambda r: lambda t: f"(vmap vni{t} ((a zn)) (a64_frint{r}_{t} a))")(r), 3)
    for r, code in (("n", 0), ("p", 1), ("m", 2), ("z", 3), ("a", 4))]
for op, code, value, latency in UNARY:
    for s, t, sz in FSIZES:
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_UNARY",
            f"(hi 101) (size {sz}) (op {code}) (op2 5)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $zd, $pg, $zn",
            f"{op.upper()} of active {t}-bit float elements; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value(t)} zd))", latency=latency)

w("  ; --- float compares, vectors and #0.0: Pd = active & compare, inactive zero -")
absv = lambda t, x: f"(and vni{t} {x} {NOSIGN[t]})"
FCMP = (("fcmge", 2, 0, lambda t, a, b: f"(fcmp_ole vnf{t} {b} {a})"),
        ("fcmgt", 2, 1, lambda t, a, b: f"(fcmp_olt vnf{t} {b} {a})"),
        ("fcmeq", 3, 0, lambda t, a, b: f"(fcmp_oeq vnf{t} {a} {b})"),
        ("fcmne", 3, 1, lambda t, a, b: f"(xor vni{t} (fcmp_oeq vnf{t} {a} {b}) 1)"),
        ("fcmuo", 6, 0, lambda t, a, b: f"(fcmp_uno vnf{t} {a} {b})"),
        ("facge", 6, 1, lambda t, a, b: f"(fcmp_ole vnf{t} {absv(t, b)} {absv(t, a)})"),
        ("facgt", 7, 1, lambda t, a, b: f"(fcmp_olt vnf{t} {absv(t, b)} {absv(t, a)})"))
for op, code, ne, cmp in FCMP:
    for s, t, sz in FSIZES:
        ins(f"{op}_p_{s}", f"{op.upper()}_P_{s.upper()}", "SVE_CMP",
            f"(hi 101) (size {sz}) (zero 0) (op {code}) (ne {ne})",
            f"(pd preg i{t} out) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_p_{s} $pd, $pg, $zn, $zm",
            f"{op.upper()} of active {t}-bit float elements, inactive zero; no flags",
            f"(formal (and vni{t} {active(t)} {cmp(t, 'zn', 'zm')}))")
zero = lambda t: f"(vdup vni{t} 0)"
FCMP0 = (("fcmge", 16, 0, lambda t: f"(fcmp_ole vnf{t} {zero(t)} zn)"),
         ("fcmgt", 16, 1, lambda t: f"(fcmp_olt vnf{t} {zero(t)} zn)"),
         ("fcmlt", 17, 0, lambda t: f"(fcmp_olt vnf{t} zn {zero(t)})"),
         ("fcmle", 17, 1, lambda t: f"(fcmp_ole vnf{t} zn {zero(t)})"),
         ("fcmeq", 18, 0, lambda t: f"(fcmp_oeq vnf{t} zn {zero(t)})"),
         ("fcmne", 19, 0, lambda t: f"(xor vni{t} (fcmp_oeq vnf{t} zn {zero(t)}) 1)"))
for op, code, o3, cmp in FCMP0:
    for s, t, sz in FSIZES:
        ins(f"{op}_z0_{s}", f"{op.upper()}_Z0_{s.upper()}", "SVE_F_CMP0",
            f"(hi 101) (size {sz}) (op {code}) (op2 1) (o3 {o3})",
            f"(pd preg i{t} out) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_z0_{s} $pd, $pg, $zn",
            f"{op.upper()} of active {t}-bit float elements against +0.0, inactive zero",
            f"(formal (and vni{t} {active(t)} {cmp(t)}))")

w("  ; --- float reductions into element 0 of Vd -------------------------------")
# Arm's FMAXV/FMINV/FMAXNMV/FMINNMV combine elements pairwise, recursively, with
# inactive elements the operation's identity. Written as that tree, every level
# nests the one below inside an FMAX whose NaN and zero rules name each operand
# several times, and the executors, which inline bindings, rendered FMAXV.H to
# 142 MB of C. So each is described as what the tree provably computes:
#
#   FMAXV/FMINV: FMAX propagates any NaN to the root, so a NaN among the
#     active elements makes the default NaN; otherwise it is an integer max
#     (min) over sortable keys -- the key orders +0 above -0, which is Arm's
#     rule for two zeros, and the integer reduction is one call per lane.
#   FMAXNMV/FMINNMV: a signalling NaN matters only at the first level, where
#     it makes its pair the default NaN; above that the only NaNs are quiet
#     and mean "missing", so the rest is a max (min) that ignores NaNs. The
#     first level stays Arm's own FMAXNM, applied once.
ALL = {16: "0xffff", 32: "0xffffffff", 64: "0xffffffffffffffff"}
def key(t, x):
    return f"(xor vni{t} {x} (or vni{t} (ashr vni{t} {x} (vdup vni{t} {t - 1})) {SIGN[t]}))"
def unkey(t, k):
    return f"(xor i{t} {k} (select i{t} (icmp_ne i{t} (and i{t} {k} {SIGN[t]}) 0) {SIGN[t]} {ALL[t]}))"
def red_minmax(op, t, m):
    red = "vredmaxu" if "max" in op else "vredminu"
    if op in ("fmax", "fmin"):
        any_nan = f"(vredor vni{t} (fcmp_uno vnf{t} {m} {m}))"
        k = f"({red} vni{t} {key(t, m)})"
        return f"(select i{t} (icmp_ne i{t} {any_nan} 0) {DNAN[t]} {unkey(t, k)})"
    first = fminmax(op, t, f"(vuzp1 vni{t} {m} {m})", f"(vuzp2 vni{t} {m} {m})")
    missing = "0" if "max" in op else ALL[t]
    k = f"({red} vni{t} (vmerge vni{t} (fcmp_uno vnf{t} {first} {first}) {missing} {key(t, first)}))"
    return f"(select i{t} (icmp_eq i{t} {k} {missing}) {DNAN[t]} {unkey(t, k)})"
for op, code, ident in (("faddv", 0, None), ("fmaxnmv", 4, DNAN), ("fminnmv", 5, DNAN),
                        ("fmaxv", 6, NINF), ("fminv", 7, PINF)):
    for s, t, sz in FSIZES:
        if op == "faddv":
            value = f"(vfredpsum vnf{t} (vmerge vni{t} {active(t)} zn 0))"
        else:
            value = red_minmax(op[:-1], t, f"(vmerge vni{t} {active(t)} zn {ident[t]})")
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_RED",
            f"(hi 101) (size {sz}) (op {code}) (op2 1)",
            f"(vd vreg i{t} out) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $vd, $pg, $zn",
            f"{op.upper()} of the active {t}-bit float elements, as Arm's pairwise tree computes it, into element 0",
            lane0(t, value), latency=6)
# FADDA is strictly ordered from Vdn's element 0. An inactive element adds
# -0.0, which is the identity for every number and, under DN, for every NaN
# after the first add -- so only "no element active" needs its own case: Arm
# leaves the start value alone, NaN included.
for s, t, sz in FSIZES:
    m = f"(vmerge vni{t} {active(t)} zm {NZERO[t]})"
    chain = f"(vextract vni{t} zdn 0)"
    for k in range(VL // t):
        chain = f"(fadd f{t} {chain} (vextract vni{t} {m} {k}))"
    anyv = f"(vredor vni{t} {active(t)})"
    value = f"(select i{t} (icmp_ne i{t} {anyv} 0) {chain} (vextract vni{t} zdn 0))"
    ins(f"fadda_{s}", f"FADDA_{s.upper()}", "SVE_F_RED_A",
        f"(hi 101) (size {sz}) (op 24) (op2 1)",
        # Every lane reads element 0 of the register it writes, so, as EXT's
        # is, the source is declared apart: a destination, and a source
        # derived from it.
        f"(zd vreg i{t} out) (zdn vreg i{t} in (derive zd 0)) (pg preg i{t} in) (zm vreg i{t} in)",
        f"fadda_{s} $zd, $pg, $zm",
        "FADDA: Vdn plus the active elements, strictly in order, into element 0",
        lane0(t, value), latency=8)

# ---- conversions (V4b) --------------------------------------------------------
# Each element sits in a container the wider of its two sizes: SCVTF Zd.S,
# Zn.D reads a 64-bit integer and writes a 32-bit float into the low half of
# the same 64-bit element. Arm zero-extends a float result into its container
# and extends an integer one by its own signedness (FCVTZS sign-extends, FCVTZU
# zero-extends). Inactive containers keep Zd.
W = {"h": 16, "s": 32, "d": 64}
SZ = {16: 1, 32: 2, 64: 3}
CVT = []
for signed, u in (("s", 0), ("u", 1)):
    for (d, sw), code in ((("h", "h"), 0x12), (("h", "s"), 0x14), (("h", "d"), 0x16), (("s", "s"), 0x14),
                          (("s", "d"), 0x14), (("d", "s"), 0x10), (("d", "d"), 0x16)):
        size = {("h", "h"): 1, ("h", "s"): 1, ("h", "d"): 1, ("s", "s"): 2}.get((d, sw), 3)
        CVT.append((f"{signed}cvtf", d, sw, size, code | u,
                    lambda dw, swd, c, sg=signed: f"(zext i{c} {dw} (fcvt_{sg}2f f{dw} {swd} a))"))
    for (d, sw), code in ((("h", "h"), 0x1a), (("s", "h"), 0x1c), (("d", "h"), 0x1e), (("s", "s"), 0x1c),
                          (("d", "s"), 0x1c), (("s", "d"), 0x18), (("d", "d"), 0x1e)):
        size = {("h", "h"): 1, ("s", "h"): 1, ("d", "h"): 1, ("s", "s"): 2}.get((d, sw), 3)
        ext = "sext" if signed == "s" else "zext"
        CVT.append((f"fcvtz{signed}", d, sw, size, code | u,
                    lambda dw, swd, c, sg=signed, ext=ext: f"({ext} i{c} {dw} (fcvt_f2{sg} i{dw} {swd} a))"))
for (d, sw), size, code in ((("s", "h"), 2, 0x09), (("d", "h"), 3, 0x09), (("h", "s"), 2, 0x08),
                            (("d", "s"), 3, 0x0b), (("h", "d"), 3, 0x08), (("s", "d"), 3, 0x0a)):
    CVT.append(("fcvt", d, sw, size, code, lambda dw, swd, c: f"(zext i{c} {dw} (fcvt_f2f f{dw} {swd} a))"))
w("  ; --- SCVTF/UCVTF/FCVTZS/FCVTZU/FCVT, every size pair, merging --------------")
for op, d, sw, size, code, body in CVT:
    dw, swd = W[d], W[sw]
    c = max(dw, swd)
    name = f"{op}_{d}{sw}"
    ins(name, name.upper(), "SVE_F_UNARY", f"(hi 101) (size {size}) (op {code}) (op2 5)",
        f"(zd vreg i{c} inout) (pg preg i{c} in) (zn vreg i{c} in)", f"{name} $zd, $pg, $zn",
        f"{op.upper()} Zd.{d.upper()} from Zn.{sw.upper()} in {c}-bit containers, where active",
        f"(formal (vmerge vni{c} {active(c)} (vmap vni{c} ((a zn)) {body(dw, swd, c)}) zd))", latency=4)

# ---- widening and narrowing (V4c) ----------------------------------------------
# SVE widens within one register: a wide element's two halves are a narrow
# even ("bottom") and odd ("top") element, so every form here is lane-local at
# the WIDE type -- the bottom half of a wide lane is its low bits, the top its
# high bits. UNPKLO/HI are the exception, reading narrow element l, which
# sits in wide lane l/2; ZIP1/ZIP2 at the wide type put that lane in place and
# the lane's parity picks the half. Narrowing writes the low half of each wide
# lane and zeroes the high ("B"), or writes the high half and keeps the low
# ("T", destructive).
WIDE = [("h", 16, 1), ("s", 32, 2), ("d", 64, 3)]
w("  ; --- SUNPKLO/HI, UUNPKLO/HI: the low or high half, extended ----------------")
for op, u, h in (("sunpklo", 0, 0), ("sunpkhi", 0, 1), ("uunpklo", 1, 0), ("uunpkhi", 1, 1)):
    for s, t, sz in WIDE:
        n = t // 2
        ext = "zext" if u else "sext"
        zip_ = "vzip2" if h else "vzip1"
        body = (f"(vmap vni{t} ((a ({zip_} vni{t} zn zn)) (odd (and vni{t} (vid vni{t}) 1))) "
                f"({ext} i{t} {n} (select i{t} (icmp_ne i{t} odd 0) (lshr i{t} a {n}) a)))")
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_UNPK",
            f"(hi 5) (size {sz}) (op 12) (u {u}) (h {h}) (op2 14)",
            f"(zd vreg i{t} out) (zn vreg i{t} in)", f"{op}_{s} $zd, $zn",
            f"{op.upper()}: the {'high' if h else 'low'} half's {n}-bit elements, "
            f"{'zero' if u else 'sign'}-extended to {t} bits", f"(formal {body})")
w("  ; --- SXTB/H/W, UXTB/H/W: extend within the element, merging ----------------")
for op, opc, bits, sizes in (("sxtb", 0, 8, "hsd"), ("uxtb", 1, 8, "hsd"), ("sxth", 2, 16, "sd"),
                             ("uxth", 3, 16, "sd"), ("sxtw", 4, 32, "d"), ("uxtw", 5, 32, "d")):
    for s, t, sz in WIDE:
        if s not in sizes:
            continue
        ext = "zext" if op[0] == "u" else "sext"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_UNARY_INT",
            f"(hi 4) (size {sz}) (op 2) (opc {opc}) (op2 5)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $zd, $pg, $zn",
            f"{op.upper()}: the low {bits} bits of each active {t}-bit element, extended",
            f"(formal (vmerge vni{t} {active(t)} (vmap vni{t} ((a zn)) ({ext} i{t} {bits} a)) zd))")
w("  ; --- SVE2 widening: SADDL/UADDL/SSUBL/USUBL/SMULL/UMULL, bottom and top ----")
for op, code, kind, top in (("saddlb", 0, "add s", 0), ("saddlt", 1, "add s", 1), ("uaddlb", 2, "add u", 0),
                            ("uaddlt", 3, "add u", 1), ("ssublb", 4, "sub s", 0), ("usublb", 6, "sub u", 0),
                            ("smullb", 28, "mul s", 0), ("smullt", 29, "mul s", 1),
                            ("umullb", 30, "mul u", 0), ("umullt", 31, "mul u", 1)):
    arith, sign = kind.split()
    for s, t, sz in WIDE:
        n = t // 2
        ext = "sext" if sign == "s" else "zext"
        half = (lambda x: f"(lshr i{t} {x} {n})") if top else (lambda x: x)
        body = f"(vmap vni{t} ((a zn) (b zm)) ({arith} i{t} ({ext} i{t} {n} {half('a')}) ({ext} i{t} {n} {half('b')})))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE",
            f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: the {'odd' if top else 'even'} {n}-bit elements, {'signed' if sign == 's' else 'unsigned'}, "
            f"{arith} at {t} bits", f"(formal {body})")
w("  ; --- SVE2 narrowing: ADDHN/SUBHN, SQXTN/UQXTN/SQXTUN, bottom and top -------")
def narrow_put(t, n, value, top):
    if top:
        return f"(or i{t} (shl i{t} {value} {n}) (and i{t} d (sub i{t} (shl i{t} 1 {n}) 1)))"
    return f"(and i{t} {value} (sub i{t} (shl i{t} 1 {n}) 1))"
for op, code, arith, top in (("addhnb", 24, "add", 0), ("addhnt", 25, "add", 1),
                             ("subhnb", 28, "sub", 0), ("subhnt", 29, "sub", 1)):
    for s, t, sz in WIDE:
        n = t // 2
        value = narrow_put(t, n, f"(lshr i{t} ({arith} i{t} a b) {n})", top)
        dst = f"(zd vreg i{t} inout)" if top else f"(zd vreg i{t} out)"
        binding = "((a zn) (b zm) (d zd))" if top else "((a zn) (b zm))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE",
            f"(hi 69) (size {sz}) (zero 1) (op {code})",
            f"{dst} (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: the high half of each {t}-bit {arith}, into the {'odd' if top else 'even'} "
            f"{n}-bit elements{'; the even ones keep Zd' if top else ', the odd ones zero'}",
            f"(formal (vmap vni{t} {binding} {value}))")
for op, opc, sat in (("sqxtn", 0, "s"), ("uqxtn", 1, "u"), ("sqxtun", 2, "su")):
    for top in (0, 1):
        for s, t, sz in WIDE:
            n = t // 2
            smax, smin, umax = (1 << (n - 1)) - 1, (1 << t) - (1 << (n - 1)), (1 << n) - 1
            if sat == "s":
                v = (f"(select i{t} (icmp_slt i{t} {smax} a) {smax} "
                     f"(select i{t} (icmp_slt i{t} a {smin}) {smin} a))")
            elif sat == "u":
                v = f"(select i{t} (icmp_ult i{t} {umax} a) {umax} a)"
            else:
                v = (f"(select i{t} (icmp_slt i{t} a 0) 0 "
                     f"(select i{t} (icmp_slt i{t} {umax} a) {umax} a))")
            value = narrow_put(t, n, v, top)
            name = f"{op}{'t' if top else 'b'}"
            tszh, tszl = {16: (0, 1), 32: (0, 2), 64: (1, 0)}[t]
            dst = f"(zd vreg i{t} inout)" if top else f"(zd vreg i{t} out)"
            binding = "((a zn) (d zd))" if top else "((a zn))"
            ins(f"{name}_{s}", f"{name.upper()}_{s.upper()}", "SVE2_XTN",
                f"(hi 138) (tszh {tszh}) (one 1) (tszl {tszl}) (zero 0) (op 2) (opc {opc}) (t {top})",
                f"{dst} (zn vreg i{t} in)", f"{name}_{s} $zd, $zn",
                f"{name.upper()}: each {t}-bit element saturated to {n} bits, into the "
                f"{'odd' if top else 'even'} elements{'; the even ones keep Zd' if top else ', the odd ones zero'}",
                f"(formal (vmap vni{t} {binding} {value}))")

# ---- gathers and scatters (V4d) -------------------------------------------------
# Word and doubleword elements, each lane its own address: Xn plus Zm's lane
# (extended from 32 bits by UXTW or SXTW, or all 64, and scaled or not), or
# Zn's lane plus an immediate. Loads are Pg/Z; stores write active lanes only.
GATHER = (
    # name, element, fixed high bits, op, offset form, scale
    ("ld1w_gu", 32, 0x85004000, "uxtw", 0), ("ld1w_gs", 32, 0x85404000, "sxtw", 0),
    ("ld1w_gus", 32, 0x85204000, "uxtw", 2), ("ld1w_gss", 32, 0x85604000, "sxtw", 2),
    ("ld1d_gx", 64, 0xc5c0c000, "x", 0), ("ld1d_gxs", 64, 0xc5e0c000, "x", 3),
    ("ld1d_gus", 64, 0xc5a04000, "uxtw", 3), ("ld1d_gss", 64, 0xc5e04000, "sxtw", 3),
    ("st1w_gus", 32, 0xe5608000, "uxtw", 2), ("st1w_gss", 32, 0xe560c000, "sxtw", 2),
    ("st1d_gx", 64, 0xe580a000, "x", 0), ("st1d_gxs", 64, 0xe5a0a000, "x", 3),
)
def offset(t, form, scale):
    # A scalar operation inside a scalable one is applied lane by lane, so the
    # index needs no `vmap` -- which a behavior, unlike a formal, cannot hold.
    lane = {"uxtw": "(zext i64 32 zm)", "sxtw": "(sext i64 32 zm)", "x": "zm"}[form]
    return f"(shl i64 {lane} {scale})"
w("  ; --- gathers and scatters: [Xn, Zm, (U|S)XTW|LSL #s] ------------------------")
for name, t, word, form, scale in GATHER:
    hi, op = word >> 21, (word >> 13) & 7
    load = name.startswith("ld")
    addr = f"(vload_indexed vni{t} rn {offset(t, form, scale)})"
    if load:
        body = (f"(behavior (when (ne {active(t)} 0) (set zt {addr})) "
                f"(when (eq {active(t)} 0) (set zt 0)))")
    else:
        body = (f"(behavior (when (ne {active(t)} 0) "
                f"(store (vaddr_indexed vni{t} rn {offset(t, form, scale)}) zt i{t})))")
    ins(name, name.upper(), "SVE_GATHER", f"(hi {hi}) (op {op})",
        f"(zt vreg i{t} {'out' if load else 'in'}) (pg preg i{t} in) (rn a64_gpr64sp i64 in) (zm vreg i{t} in)",
        f"{name} $zt, $pg, $rn, $zm",
        f"{name.split('_')[0].upper()}: each active {t}-bit element at Xn + "
        + {"uxtw": "UXTW(Zm)", "sxtw": "SXTW(Zm)", "x": "Zm"}[form]
        + (f" << {scale}" if scale else "") + ("; inactive zero" if load else ""),
        body, latency=6, category="custom")
w("  ; --- gathers and scatters: [Zn, #imm], the immediate scaled by the element --")
for name, t, word in (("ld1w_gi", 32, 0x8521c000), ("ld1d_gi", 64, 0xc5a1c000),
                      ("st1w_gi", 32, 0xe561a000), ("st1d_gi", 64, 0xe5c1a000)):
    hi, op = word >> 21, (word >> 13) & 7
    load = name.startswith("ld")
    scaled = f"(mul i64 (zext i64 5 imm) {t // 8})"
    index = "(zext i64 32 zn)" if t == 32 else "(add i64 zn 0)"
    if load:
        body = (f"(behavior (when (ne {active(t)} 0) (set zt (vload_indexed vni{t} {scaled} {index}))) "
                f"(when (eq {active(t)} 0) (set zt 0)))")
    else:
        body = (f"(behavior (when (ne {active(t)} 0) "
                f"(store (vaddr_indexed vni{t} {scaled} {index}) zt i{t})))")
    ins(name, name.upper(), "SVE_GATHER_I", f"(hi {hi}) (op {op})",
        f"(zt vreg i{t} {'out' if load else 'in'}) (pg preg i{t} in) (zn vreg i{t} in) (imm imm i5 in)",
        f"{name} $zt, $pg, $zn, $imm",
        f"{name.split('_')[0].upper()}: each active {t}-bit element at Zn's lane + imm * {t // 8}"
        + ("; inactive zero" if load else ""), body, latency=6, category="custom")

# ---- SVE2 integer arithmetic (V5a) ----------------------------------------------
w("  ; --- saturating arithmetic: the A64 corpus's own defsems ----------------------")
for line in defsems([f"a64_{op}_{t}" for t in (8, 16, 32, 64)
                     for op in ("sqadd", "uqadd", "sqsub", "uqsub")]):
    w(line)
w("")
def sat(op, t, a, b):
    return f"(vmap vni{t} ((a {a}) (b {b})) (a64_{op}_{t} a b))"
MINV = {8: "0x80", 16: "0x8000", 32: "0x80000000", 64: "0x8000000000000000"}
MAXV = {8: "0x7f", 16: "0x7fff", 32: "0x7fffffff", 64: "0x7fffffffffffffff"}
w("  ; --- SQADD/UQADD/SQSUB/UQSUB, SMULH/UMULH, SQDMULH/SQRDMULH (unpredicated) -")
def sqdmulh(t, rounding):
    # 2ab >> T from the product's halves, rounded by 2^(T-1) first when asked:
    # bit T-1 of the low half carries into the result's lowest bit. The only
    # product that does not fit is MIN * MIN, which saturates.
    if rounding:
        low = f"(add i{t} (mul i{t} a b) {1 << (t - 2)})"
        carry = f"(select i{t} (icmp_ult i{t} {low} (mul i{t} a b)) 1 0)"
        high = f"(add i{t} (mulh i{t} a b) {carry})"
    else:
        low, high = f"(mul i{t} a b)", f"(mulh i{t} a b)"
    value = f"(or i{t} (shl i{t} {high} 1) (lshr i{t} {low} {t - 1}))"
    both_min = f"(and i{t} (icmp_eq i{t} a {MINV[t]}) (icmp_eq i{t} b {MINV[t]}))"
    return f"(vmap vni{t} ((a zn) (b zm)) (select i{t} {both_min} {MAXV[t]} {value}))"
for op, code, value in (("sqadd", 4, lambda t: sat("sqadd", t, "zn", "zm")),
                        ("uqadd", 5, lambda t: sat("uqadd", t, "zn", "zm")),
                        ("sqsub", 6, lambda t: sat("sqsub", t, "zn", "zm")),
                        ("uqsub", 7, lambda t: sat("uqsub", t, "zn", "zm")),
                        ("smulh", 26, lambda t: f"(vmap vni{t} ((a zn) (b zm)) (mulh i{t} a b))"),
                        ("umulh", 27, lambda t: f"(vmap vni{t} ((a zn) (b zm)) (mulhu i{t} a b))"),
                        ("sqdmulh", 28, lambda t: sqdmulh(t, False)),
                        ("sqrdmulh", 29, lambda t: sqdmulh(t, True))):
    for s, t, sz in SIZES:
        ins(f"{op}_z_{s}", f"{op.upper()}_Z_{s.upper()}", "SVE_INT_UNPRED",
            f"(hi 4) (size {sz}) (one 1) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_z_{s} $zd, $zn, $zm",
            f"{op.upper()} of every {t}-bit element", f"(formal {value(t)})", latency=3)

w("  ; --- halving, saturating and absolute-difference arithmetic, predicated ------")
def halve(t, signed, op, a, b):
    shr = "ashr" if signed else "lshr"
    half = lambda x: f"({shr} i{t} {x} 1)"
    if op == "add":
        carry = f"(and i{t} (and i{t} {a} {b}) 1)"
        return f"(add i{t} (add i{t} {half(a)} {half(b)}) {carry})"
    if op == "radd":
        carry = f"(and i{t} (or i{t} {a} {b}) 1)"
        return f"(add i{t} (add i{t} {half(a)} {half(b)}) {carry})"
    borrow = f"(and i{t} (and i{t} (xor i{t} {a} {ALL8[t]}) {b}) 1)"
    return f"(sub i{t} (sub i{t} {half(a)} {half(b)}) {borrow})"
ALL8 = {8: "0xff", 16: "0xffff", 32: "0xffffffff", 64: "0xffffffffffffffff"}
def pair(t, body):
    return f"(vmap vni{t} ((a zd) (b zm)) {body})"
def absdiff(t, signed, a, b):
    less = f"(icmp_slt i{t} {a} {b})" if signed else f"(icmp_ult i{t} {a} {b})"
    return f"(select i{t} {less} (sub i{t} {b} {a}) (sub i{t} {a} {b}))"
def suqadd(t):
    # Signed Zdn plus unsigned Zm can only overflow upward, and it does
    # exactly when Zm exceeds MAX - Zdn -- which, taken unsigned, is exact for
    # either sign of Zdn.
    return f"(select i{t} (icmp_ult i{t} (sub i{t} {MAXV[t]} a) b) {MAXV[t]} (add i{t} a b))"
def usqadd(t):
    # Unsigned Zdn plus signed Zm, saturated to the unsigned range.
    wide = f"(add i{t} a b)"
    return (f"(select i{t} (icmp_slt i{t} b 0) "
            f"(select i{t} (icmp_ult i{t} a (sub i{t} 0 b)) 0 {wide}) "
            f"(select i{t} (icmp_ult i{t} {wide} a) {ALL8[t]} {wide}))")
PRED2 = (("shadd", 1, 0, lambda t: pair(t, halve(t, True, "add", "a", "b"))),
         ("uhadd", 1, 1, lambda t: pair(t, halve(t, False, "add", "a", "b"))),
         ("shsub", 1, 2, lambda t: pair(t, halve(t, True, "sub", "a", "b"))),
         ("uhsub", 1, 3, lambda t: pair(t, halve(t, False, "sub", "a", "b"))),
         ("srhadd", 1, 4, lambda t: pair(t, halve(t, True, "radd", "a", "b"))),
         ("urhadd", 1, 5, lambda t: pair(t, halve(t, False, "radd", "a", "b"))),
         ("shsubr", 1, 6, lambda t: pair(t, halve(t, True, "sub", "b", "a"))),
         ("uhsubr", 1, 7, lambda t: pair(t, halve(t, False, "sub", "b", "a"))),
         ("sqadd", 1, 8, lambda t: sat("sqadd", t, "zd", "zm")),
         ("uqadd", 1, 9, lambda t: sat("uqadd", t, "zd", "zm")),
         ("sqsub", 1, 10, lambda t: sat("sqsub", t, "zd", "zm")),
         ("uqsub", 1, 11, lambda t: sat("uqsub", t, "zd", "zm")),
         ("suqadd", 1, 12, lambda t: pair(t, suqadd(t))),
         ("usqadd", 1, 13, lambda t: pair(t, usqadd(t))),
         ("sqsubr", 1, 14, lambda t: sat("sqsub", t, "zm", "zd")),
         ("uqsubr", 1, 15, lambda t: sat("uqsub", t, "zm", "zd")))
for op, zero, opc, value in PRED2:
    for s, t, sz in SIZES:
        ins(f"{op}_m_{s}", f"{op.upper()}_M_{s.upper()}", "SVE_F_PRED",
            f"(hi 68) (size {sz}) (zero {zero}) (opc {opc}) (op 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"{op}_m_{s} $zd, $pg, $zm",
            f"{op.upper()} of active {t}-bit elements into Zdn; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value(t)} zd))")
for op, zero, opc, value in (("sabd", 0, 12, lambda t: pair(t, absdiff(t, True, "a", "b"))),
                             ("uabd", 0, 13, lambda t: pair(t, absdiff(t, False, "a", "b"))),
                             ("smulh", 1, 2, lambda t: pair(t, f"(mulh i{t} a b)")),
                             ("umulh", 1, 3, lambda t: pair(t, f"(mulhu i{t} a b)"))):
    for s, t, sz in SIZES:
        ins(f"{op}_m_{s}", f"{op.upper()}_M_{s.upper()}", "SVE_F_PRED",
            f"(hi 4) (size {sz}) (zero {zero}) (opc {opc}) (op 0)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"{op}_m_{s} $zd, $pg, $zm",
            f"{op.upper()} of active {t}-bit elements into Zdn; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value(t)} zd))")
for op, code, body in (("sqabs", 8, lambda t: f"(select i{t} (icmp_eq i{t} a {MINV[t]}) {MAXV[t]} "
                                              f"(select i{t} (icmp_slt i{t} a 0) (sub i{t} 0 a) a))"),
                       ("sqneg", 9, lambda t: f"(select i{t} (icmp_eq i{t} a {MINV[t]}) {MAXV[t]} (sub i{t} 0 a))")):
    for s, t, sz in SIZES:
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_UNARY",
            f"(hi 68) (size {sz}) (op {code}) (op2 5)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $zd, $pg, $zn",
            f"{op.upper()} of active {t}-bit elements, MIN saturating to MAX; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} (vmap vni{t} ((a zn)) {body(t)}) zd))")

w("  ; --- pairwise: ADDP/SMAXP/UMAXP/SMINP/UMINP -----------------------------------")
# Element i of the result pairs Zdn[i], Zdn[i+1] when i is even and Zm[i-1],
# Zm[i] when it is odd -- exactly TRN1 and TRN2 of (Zdn, Zm). Zdn is read at a
# lane it does not write, so it is declared apart from the destination.
PAIRWISE = (("addp", 1, lambda t: "(add i{t} a b)".format(t=t)),
            ("smaxp", 4, lambda t: f"(select i{t} (icmp_slt i{t} a b) b a)"),
            ("umaxp", 5, lambda t: f"(select i{t} (icmp_ult i{t} a b) b a)"),
            ("sminp", 6, lambda t: f"(select i{t} (icmp_slt i{t} b a) b a)"),
            ("uminp", 7, lambda t: f"(select i{t} (icmp_ult i{t} b a) b a)"))
for op, opc, body in PAIRWISE:
    for s, t, sz in SIZES:
        value = f"(vmap vni{t} ((a (vtrn1 vni{t} zdn zm)) (b (vtrn2 vni{t} zdn zm))) {body(t)})"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_PRED",
            f"(hi 68) (size {sz}) (zero 1) (opc {opc}) (op 5)",
            f"(zd vreg i{t} out) (zdn vreg i{t} in (derive zd 0)) (pg preg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $zd, $pg, $zm",
            f"{op.upper()}: adjacent pairs of Zdn into the even elements, of Zm into the odd; "
            f"inactive unchanged", f"(formal (vmerge vni{t} {active(t)} {value} zdn))")

w("  ; --- SABA/UABA, and the long forms: S/UMLAL, S/UMLSL, S/UABAL, S/UABDL ------")
for op, code, signed in (("saba", 62, True), ("uaba", 63, False)):
    for s, t, sz in SIZES:
        body = f"(add i{t} d {absdiff(t, signed, 'a', 'b')})"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: Zda plus the absolute difference of each {t}-bit pair",
            f"(formal (vmap vni{t} ((d zd) (a zn) (b zm)) {body}))")
LONG = []
for base_op, hi, code0, kind in (("mlal", 68, 16, "mla"), ("mlsl", 68, 20, "mls"),
                                 ("abal", 69, 48, "aba"), ("abdl", 69, 12, "abd")):
    for k, (sign, top) in enumerate((("s", 0), ("s", 1), ("u", 0), ("u", 1))):
        LONG.append((f"{sign}{base_op}{'t' if top else 'b'}", hi, code0 + k, kind, sign, top))
for op, hi, code, kind, sign, top in LONG:
    for s, t, sz in WIDE:
        n = t // 2
        ext = "sext" if sign == "s" else "zext"
        half = (lambda x: f"(lshr i{t} {x} {n})") if top else (lambda x: x)
        a, b = f"({ext} i{t} {n} {half('a')})", f"({ext} i{t} {n} {half('b')})"
        body = {"mla": f"(add i{t} d (mul i{t} {a} {b}))", "mls": f"(sub i{t} d (mul i{t} {a} {b}))",
                "aba": f"(add i{t} d {absdiff(t, True, a, b)})", "abd": absdiff(t, True, a, b)}[kind]
        accumulate = kind != "abd"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi {hi}) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} {'inout' if accumulate else 'out'}) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: the {'odd' if top else 'even'} {n}-bit elements, "
            f"{'signed' if sign == 's' else 'unsigned'}, at {t} bits",
            f"(formal (vmap vni{t} ({'(d zd) ' if accumulate else ''}(a zn) (b zm)) {body}))")

# ---- SVE2 shifts by immediate (V5b) -----------------------------------------------
# tsz:imm3 carries the element size (its leading one) and the amount: a left
# shift is the field's low bits, a right shift esize minus them. Rounding adds
# the last bit shifted out, which is exact where "add 2^(s-1) first" would
# overflow the element.
SHBITS = {8: 3, 16: 4, 32: 5, 64: 6}
def amount(t, bits):
    return f"(zext i{t} {bits} sh)" if t > bits else "sh"
def right(t, bits):
    return f"(sub i{t} {t} {amount(t, bits)})"
def rshift(t, x, s, signed, rounding):
    shr = "ashr" if signed else "lshr"
    value = f"({shr} i{t} {x} {s})"
    if rounding:
        # The last bit shifted out, of the value as the shift sees it: signed,
        # a shift past the element reads the sign there, so a negative number
        # rounded right by more than its width comes back 0 and not -1.
        value = f"(add i{t} {value} (and i{t} ({shr} i{t} {x} (sub i{t} {s} 1)) 1))"
    return value
def sat_left(t, x, s, kind):
    shifted = f"(shl i{t} {x} {s})"
    if kind == "s":
        back = f"(ashr i{t} {shifted} {s})"
        limit = f"(select i{t} (icmp_slt i{t} {x} 0) {MINV[t]} {MAXV[t]})"
        return f"(select i{t} (icmp_eq i{t} {back} {x}) {shifted} {limit})"
    back = f"(lshr i{t} {shifted} {s})"
    value = f"(select i{t} (icmp_eq i{t} {back} {x}) {shifted} {ALL8[t]})"
    return value if kind == "u" else f"(select i{t} (icmp_slt i{t} {x} 0) 0 {value})"
def asrd(t, x, s):
    mask = f"(sub i{t} (shl i{t} 1 {s}) 1)"
    inexact = f"(and i{t} (icmp_slt i{t} {x} 0) (icmp_ne i{t} (and i{t} {x} {mask}) 0))"
    return f"(add i{t} (ashr i{t} {x} {s}) (select i{t} {inexact} 1 0))"
PSHIFT = (("asrd", 4, lambda t, b: asrd(t, "a", right(t, b))),
          ("sqshl", 6, lambda t, b: sat_left(t, "a", amount(t, b), "s")),
          ("uqshl", 7, lambda t, b: sat_left(t, "a", amount(t, b), "u")),
          ("srshr", 12, lambda t, b: rshift(t, "a", right(t, b), True, True)),
          ("urshr", 13, lambda t, b: rshift(t, "a", right(t, b), False, True)),
          ("sqshlu", 15, lambda t, b: sat_left(t, "a", amount(t, b), "su")))
w("  ; --- predicated shifts by immediate: ASRD, SQSHL/UQSHL/SQSHLU, SRSHR/URSHR --")
for op, code, body in PSHIFT:
    for s, t, sz in SIZES:
        bits = SHBITS[t]
        enc = {8: "(tszh 0) (tszl 1)", 16: "(tszh 0) (tszl 1)", 32: "(tszh 1)", 64: "(tszh 1)"}[t]
        ins(f"{op}_i_{s}", f"{op.upper()}_I_{s.upper()}", f"SVE_PSHIFT_{s.upper()}",
            f"(hi 4) {enc} (op {code}) (op2 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (sh imm i{bits} in)", f"{op}_i_{s} $zd, $pg, $sh",
            f"{op.upper()} of active {t}-bit elements by an immediate; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} (vmap vni{t} ((a zd)) {body(t, bits)}) zd))")
w("  ; --- SSRA/USRA/SRSRA/URSRA, SRI/SLI: shift, then accumulate or insert ------")
ACC = (("ssra", 14, 0, lambda t, b: f"(add i{t} d {rshift(t, 'a', right(t, b), True, False)})"),
       ("usra", 14, 1, lambda t, b: f"(add i{t} d {rshift(t, 'a', right(t, b), False, False)})"),
       ("srsra", 14, 2, lambda t, b: f"(add i{t} d {rshift(t, 'a', right(t, b), True, True)})"),
       ("ursra", 14, 3, lambda t, b: f"(add i{t} d {rshift(t, 'a', right(t, b), False, True)})"),
       ("sri", 15, 0, lambda t, b: f"(or i{t} (and i{t} d (xor i{t} (lshr i{t} {ALL8[t]} {right(t, b)}) {ALL8[t]})) "
                                   f"(lshr i{t} a {right(t, b)}))"),
       ("sli", 15, 1, lambda t, b: f"(or i{t} (and i{t} d (sub i{t} (shl i{t} 1 {amount(t, b)}) 1)) "
                                   f"(shl i{t} a {amount(t, b)}))"))
for op, code, opc, body in ACC:
    for s, t, sz in SIZES:
        bits = SHBITS[t]
        enc = {8: "(tszh 0) (tszl 1)", 16: "(tszh 0) (tszl 1)", 32: "(tszh 1)", 64: "(tszh 1)"}[t]
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", f"SVE_SHIFT_{s.upper()}",
            f"(hi 69) {enc} (one 0) (op {code}) (opc {opc})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (sh imm i{bits} in)", f"{op}_{s} $zd, $zn, $sh",
            f"{op.upper()} of every {t}-bit element of Zn by an immediate, into Zda",
            f"(formal (vmap vni{t} ((d zd) (a zn)) {body(t, bits)}))")
w("  ; --- SSHLLB/T, USHLLB/T: widen, then shift left ------------------------------")
for op, code, sign, top in (("sshllb", 40, "s", 0), ("sshllt", 41, "s", 1),
                            ("ushllb", 42, "u", 0), ("ushllt", 43, "u", 1)):
    for s, t, sz in WIDE:
        n = t // 2
        bits = SHBITS[n]
        ext = "sext" if sign == "s" else "zext"
        half = f"(lshr i{t} a {n})" if top else "a"
        enc = {16: "(tszh 0) (tszl 1)", 32: "(tszh 0) (tszl 1)", 64: "(tszh 1)"}[t]
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", f"SVE2_SHN_{s.upper()}", f"(hi 138) {enc} (zero 0) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (sh imm i{bits} in)", f"{op}_{s} $zd, $zn, $sh",
            f"{op.upper()}: the {'odd' if top else 'even'} {n}-bit elements, extended, shifted left",
            f"(formal (vmap vni{t} ((a zn)) (shl i{t} ({ext} i{t} {n} {half}) {amount(t, bits)})))")
w("  ; --- narrowing shifts right: SHRN/RSHRN/SQSHRN/SQRSHRN/UQSHRN/UQRSHRN/SQSHRUN/SQRSHRUN")
NSHIFT = []
for base_op, code0, signed, sat_kind in (("sqshrun", 0, True, "su"), ("shrn", 4, False, None),
                                         ("sqshrn", 8, True, "s"), ("uqshrn", 12, False, "u")):
    for k, rounding in enumerate((False, True)):
        name = base_op if not rounding else base_op.replace("shr", "rshr")
        NSHIFT.append((name, code0 + 2 * k, signed, sat_kind, rounding))
for op, code, signed, sat_kind, rounding in NSHIFT:
    for top in (0, 1):
        for s, t, sz in WIDE:
            n = t // 2
            bits = SHBITS[n]
            s_amt = f"(sub i{t} {n} {amount(t, bits)})"
            v = rshift(t, "a", s_amt, signed, rounding)
            smax, smin, umax = (1 << (n - 1)) - 1, (1 << t) - (1 << (n - 1)), (1 << n) - 1
            if sat_kind == "s":
                v = f"(select i{t} (icmp_slt i{t} {smax} {v}) {smax} (select i{t} (icmp_slt i{t} {v} {smin}) {smin} {v}))"
            elif sat_kind == "u":
                v = f"(select i{t} (icmp_ult i{t} {umax} {v}) {umax} {v})"
            elif sat_kind == "su":
                v = f"(select i{t} (icmp_slt i{t} {v} 0) 0 (select i{t} (icmp_slt i{t} {umax} {v}) {umax} {v}))"
            value = narrow_put(t, n, v, top)
            name = f"{op}{'t' if top else 'b'}"
            enc = {16: "(tszh 0) (tszl 1)", 32: "(tszh 0) (tszl 1)", 64: "(tszh 1)"}[t]
            dst = f"(zd vreg i{t} inout)" if top else f"(zd vreg i{t} out)"
            binding = "((a zn) (d zd))" if top else "((a zn))"
            ins(f"{name}_{s}", f"{name.upper()}_{s.upper()}", f"SVE2_SHN_{s.upper()}",
                f"(hi 138) {enc} (zero 1) (op {code + top})",
                f"{dst} (zn vreg i{t} in) (sh imm i{bits} in)", f"{name}_{s} $zd, $zn, $sh",
                f"{name.upper()}: each {t}-bit element shifted right into {n} bits, the "
                f"{'odd' if top else 'even'} elements{'; the even ones keep Zd' if top else ', the odd ones zero'}",
                f"(formal (vmap vni{t} {binding} {value}))")

# ---- SVE2 bitwise, complex, table, WHILE, carry, match and histogram (V5c) -------
w("  ; --- EOR3/BCAX/BSL/BSL1N/BSL2N/NBSL: three-source bitwise, over 64-bit lanes --")
NOT = lambda x: f"(xor vni64 {x} 0xffffffffffffffff)"
TERN = (("eor3", 0, 14, "(xor vni64 (xor vni64 zd zm) zk)"),
        ("bcax", 1, 14, f"(xor vni64 zd (and vni64 zm {NOT('zk')}))"),
        ("bsl", 0, 15, f"(or vni64 (and vni64 zd zk) (and vni64 zm {NOT('zk')}))"),
        ("bsl1n", 1, 15, f"(or vni64 (and vni64 {NOT('zd')} zk) (and vni64 zm {NOT('zk')}))"),
        ("bsl2n", 2, 15, f"(or vni64 (and vni64 zd zk) (and vni64 {NOT('zm')} {NOT('zk')}))"),
        ("nbsl", 3, 15, NOT(f"(or vni64 (and vni64 zd zk) (and vni64 zm {NOT('zk')}))")))
for op, opc, code, value in TERN:
    ins(op, op.upper(), "SVE2_TERN", f"(hi 4) (opc {opc}) (one 1) (op {code})",
        "(zd vreg i64 inout) (zm vreg i64 in) (zk vreg i64 in)", f"{op} $zd, $zm, $zk",
        f"{op.upper()}: bitwise, of Zdn, Zm and Zk", f"(formal {value})")
w("  ; --- XAR: exclusive OR, then rotate right by an immediate -------------------")
for s, t, sz in SIZES:
    bits = SHBITS[t]
    enc = {8: "(tszh 0) (tszl 1)", 16: "(tszh 0) (tszl 1)", 32: "(tszh 1)", 64: "(tszh 1)"}[t]
    r = right(t, bits)
    body = f"(or i{t} (lshr i{t} (xor i{t} a b) {r}) (shl i{t} (xor i{t} a b) (sub i{t} {t} {r})))"
    ins(f"xar_{s}", f"XAR_{s.upper()}", f"SVE_SHIFT_{s.upper()}", f"(hi 4) {enc} (one 1) (op 3) (opc 1)",
        f"(zd vreg i{t} inout) (zn vreg i{t} in) (sh imm i{bits} in)", f"xar_{s} $zd, $zn, $sh",
        f"XAR: each {t}-bit element of Zdn XOR Zm, rotated right", f"(formal (vmap vni{t} ((a zd) (b zn)) {body}))")
w("  ; --- EORBT/EORTB, CADD/SQCADD: pairs of adjacent elements --------------------")
def even(t):
    return f"(icmp_eq vni{t} (and vni{t} (vid vni{t}) 1) (vdup vni{t} 0))"
for op, code in (("eorbt", 36), ("eortb", 37)):
    for s, t, sz in SIZES:
        # EORBT: even i takes Zn[i] ^ Zm[i+1] (TRN2 of Zm); EORTB: odd i takes
        # Zn[i] ^ Zm[i-1] (TRN1 of Zm). The other half keeps Zd.
        if op == "eorbt":
            value = f"(vmerge vni{t} {even(t)} (xor vni{t} zn (vtrn2 vni{t} zm zm)) zd)"
        else:
            value = f"(vmerge vni{t} {even(t)} zd (xor vni{t} zn (vtrn1 vni{t} zm zm)))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: interleaved exclusive OR of {t}-bit elements", f"(formal {value})")
for op, opcode, sat_ in (("cadd", 0, False), ("sqcadd", 1, True)):
    for rot, code in ((90, 54), (270, 55)):
        for s, t, sz in SIZES:
            swapped = f"(vmerge vni{t} {even(t)} (vtrn2 vni{t} zm zm) (vtrn1 vni{t} zm zm))"
            if sat_:
                sub_ = sat("sqsub", t, "zd", swapped)
                add_ = sat("sqadd", t, "zd", swapped)
            else:
                sub_, add_ = f"(sub vni{t} zd {swapped})", f"(add vni{t} zd {swapped})"
            value = (f"(vmerge vni{t} {even(t)} {sub_} {add_})" if rot == 90
                     else f"(vmerge vni{t} {even(t)} {add_} {sub_})")
            ins(f"{op}{rot}_{s}", f"{op.upper()}{rot}_{s.upper()}", "SVE2_CADD",
                f"(hi 69) (size {sz}) (op {opcode}) (op2 {code})",
                f"(zd vreg i{t} inout) (zm vreg i{t} in)", f"{op}{rot}_{s} $zd, $zm",
                f"{op.upper()} #{rot}: complex add of {t}-bit (real, imaginary) pairs, Zm rotated by {rot}",
                f"(formal {value})")
w("  ; --- TBX, and TBL over two registers ------------------------------------------")
for s, t, sz in SIZES:
    n = VL // t
    in_range = f"(icmp_ult vni{t} zm (vdup vni{t} {n}))"
    ins(f"tbx_{s}", f"TBX_{s.upper()}", "SVE_INT_UNPRED", f"(hi 5) (size {sz}) (one 1) (op 11)",
        f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"tbx_{s} $zd, $zn, $zm",
        f"TBX: element i reads zn[zm[i]], or keeps Zd when that index is out of range",
        f"(formal (vmerge vni{t} {in_range} (vrgather vni{t} zn zm) zd))")
    value = (f"(vmerge vni{t} {in_range} (vrgather vni{t} zn zm) "
             f"(vrgather vni{t} zn2 (sub vni{t} zm (vdup vni{t} {n}))))")
    ins(f"tbl2_{s}", f"TBL2_{s.upper()}", "SVE_INT_UNPRED", f"(hi 5) (size {sz}) (one 1) (op 10)",
        f"(zd vreg i{t} out) (zn vreg i{t} in) (zn2 vreg i{t} in (derive zn 1)) (zm vreg i{t} in)",
        f"tbl2_{s} $zd, $zn, $zm",
        f"TBL over the pair Zn, Zn+1: an index past both reads zero",
        f"(formal {value})")
w("  ; --- WHILEGE/GT/HS/HI: counting down from the top element ----------------------")
# Element e is active while Xn - (N-1-e) compares with Xm: from the top, and
# without wrapping -- with D = Xn - Xm, exact whenever Xn is not below Xm.
DOWN = (("whilege", 4, 0, "(icmp_sge i64 rn rm)", "(icmp_uge i64 D K)", "signed, >="),
        ("whilegt", 4, 1, "(icmp_slt i64 rm rn)", "(icmp_ult i64 K D)", "signed, >"),
        ("whilehs", 6, 0, "(icmp_uge i64 rn rm)", "(icmp_uge i64 D K)", "unsigned, >="),
        ("whilehi", 6, 1, "(icmp_ult i64 rm rn)", "(icmp_ult i64 K D)", "unsigned, >"))
for op, code, eq, first, lane, what in DOWN:
    for s, t, sz in SIZES:
        n = VL // t
        k = f"(sub i64 {n - 1} (zext i64 {t} (vid vni{t})))"
        d = f"(vdup vni{t} (sub i64 rn rm))"
        result = (f"(vmerge vni{t} (and i64 (vdup vni{t} {first}) "
                  f"{lane.replace('K', k).replace('D', d)}) 1 0)")
        ins(f"{op}_p_{s}", f"{op.upper()}_P_{s.upper()}", "SVE_WHILE",
            f"(hi 37) (size {sz}) (one 1) (op {code}) (eq {eq})",
            f"(pd preg i{t} out) (rn a64_gpr64 i64 in) (rm a64_gpr64 i64 in)",
            f"{op}_p_{s} $pd, $rn, $rm",
            f"From the top element down, active while Xn - k against Xm holds ({what}); NZCV from the result",
            f"(behavior (set pd {result}) {flags(t, result)})")
w("  ; --- ADCLB/T, SBCLB/T: add or subtract with carry, over element pairs ----------")
# Pair (2k, 2k+1): the even element takes Zda[2k] + Zn[2k|2k+1] + carry-in
# (bit 0 of Zm[2k+1]) and the odd one the carry out. As lanes: Zda and the
# carry-in are TRN1(Zda, Zda) and TRN2(Zm, Zm) at either parity, Zn is TRN1
# (bottom) or TRN2 (top). The odd lane reads Zda's even one, so Zda is
# declared apart from the destination.
for op, sub_, top in (("adclb", 0, 0), ("adclt", 0, 1), ("sbclb", 1, 0), ("sbclt", 1, 1)):
    for s, t, sz in (("s", 32, 0), ("d", 64, 1)):
        zn = f"(vtrn2 vni{t} zn zn)" if top else f"(vtrn1 vni{t} zn zn)"
        b = f"(xor i{t} b {ALL8[t]})" if sub_ else "b"
        body = (f"(let ((s1 (add i{t} a {b})) (s2 (add i{t} s1 (and i{t} c 1))) "
                f"(carry (or i{t} (icmp_ult i{t} s1 a) (icmp_ult i{t} s2 s1)))) "
                f"(select i{t} (icmp_eq i{t} (and i{t} l 1) 0) s2 (zext i{t} 1 carry)))")
        value = (f"(vmap vni{t} ((a (vtrn1 vni{t} zda zda)) (b {zn}) (c (vtrn2 vni{t} zm zm)) "
                 f"(l (vid vni{t}))) {body})")
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE",
            f"(hi 69) (size {sz + 2 * sub_}) (zero 0) (op {52 + top})",
            f"(zd vreg i{t} out) (zda vreg i{t} in (derive zd 0)) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: {'subtract' if sub_ else 'add'} with carry over {t}-bit element pairs",
            f"(formal {value})")
w("  ; --- MATCH/NMATCH: does each active element occur anywhere in Zm -------------")
for op, o in (("match", 0), ("nmatch", 1)):
    for s, t, sz in SIZES[:2]:
        n = VL // t
        found = f"(icmp_eq vni{t} zn (vdup vni{t} (vextract vni{t} zm 0)))"
        for j in range(1, n):
            found = f"(or vni{t} {found} (icmp_eq vni{t} zn (vdup vni{t} (vextract vni{t} zm {j}))))"
        cond = found if not o else f"(xor vni{t} {found} 1)"
        result = f"(and vni{t} {active(t)} {cond})"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_MATCH",
            f"(hi 69) (size {sz}) (one 1) (op 4) (o {o})",
            f"(pd preg i{t} out) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $pd, $pg, $zn, $zm",
            f"{op.upper()}: active elements of Zn that {'do not ' if o else ''}occur in Zm; NZCV from the result",
            f"(behavior (set pd {result}) {flags(t, result, active(t))})")
w("  ; --- HISTCNT/HISTSEG: how many elements of Zm equal each element of Zn -------")
for s, t, sz in (("s", 32, 2), ("d", 64, 3)):
    n = VL // t
    # A `vmap` body is scalar, so every element of Zm and Pg it compares
    # against is a binding -- bindings are expanded lane by lane, bodies not.
    binds = " ".join(f"(m{j} (vdup vni{t} (vextract vni{t} zm {j}))) "
                     f"(g{j} (vdup vni{t} (vextract vni{t} {active(t)} {j})))" for j in range(n))
    total = "0"
    for j in range(n):
        total = (f"(add i{t} {total} (select i{t} (and i{t} (icmp_uge i{t} l {j}) "
                 f"(and i{t} (icmp_ne i{t} g{j} 0) (icmp_eq i{t} m{j} a))) 1 0))")
    value = f"(vmerge vni{t} {active(t)} (vmap vni{t} ((a zn) (l (vid vni{t})) {binds}) {total}) 0)"
    ins(f"histcnt_{s}", f"HISTCNT_{s.upper()}", "SVE2_HIST", f"(hi 69) (size {sz}) (one 1) (op 6)",
        f"(zd vreg i{t} out) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)", f"histcnt_{s} $zd, $pg, $zn, $zm",
        "HISTCNT: for each active element, how many active elements of Zm up to it are equal to it",
        f"(formal {value})")
binds = " ".join(f"(m{j} (vdup vni8 (vextract vni8 zm {j})))" for j in range(VLB))
total = "0"
for j in range(VLB):
    total = f"(add i8 {total} (select i8 (icmp_eq i8 m{j} a) 1 0))"
ins("histseg", "HISTSEG", "SVE_INT_UNPRED", "(hi 69) (size 0) (one 1) (op 40)",
    "(zd vreg i8 out) (zn vreg i8 in) (zm vreg i8 in)", "histseg $zd, $zn, $zm",
    "HISTSEG: for each byte of Zn, how many bytes of Zm's 128-bit segment equal it",
    f"(formal (vmap vni8 ((a zn) {binds}) {total}))")

# ---- SVE2 shifts by vector, dot products and complex multiply-add (V5d) ---------
w("  ; --- SRSHL/URSHL/SQSHL/UQSHL/SQRSHL/UQRSHL: by the signed element of Zm -----")
# The amount is the WHOLE element of Zm, signed -- not its low byte, as the
# Advanced SIMD forms read it (Arm's model, asked directly). A positive amount
# shifts left, a negative one right; the R forms round a right shift, the Q
# forms saturate a left one. Amounts past the element are what the shifts give
# there: zero, a sign, or saturation.
def vshift(t, signed, rounding, saturating):
    amt = "b"
    neg = f"(sub i{t} 0 {amt})"
    left = sat_left(t, "a", amt, "s" if signed else "u") if saturating else f"(shl i{t} a {amt})"
    return f"(select i{t} (icmp_slt i{t} {amt} 0) {rshift(t, 'a', neg, signed, rounding)} {left})"
for op, opc, signed, rounding, saturating in (("srshl", 2, True, True, False), ("urshl", 3, False, True, False),
                                              ("sqshl", 8, True, False, True), ("uqshl", 9, False, False, True),
                                              ("sqrshl", 10, True, True, True), ("uqrshl", 11, False, True, True)):
    for s, t, sz in SIZES:
        ins(f"{op}_v_{s}", f"{op.upper()}_V_{s.upper()}", "SVE_F_PRED",
            f"(hi 68) (size {sz}) (zero 0) (opc {opc}) (op 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"{op}_v_{s} $zd, $pg, $zm",
            f"{op.upper()} of active {t}-bit elements by the signed element of Zm; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {pair(t, vshift(t, signed, rounding, saturating))} zd))")
w("  ; --- SDOT/UDOT: four products of quarter-width elements, into Zda ------------")
def quarter(t, x, k, signed):
    q = t // 4
    return f"({'sext' if signed else 'zext'} i{t} {q} (lshr i{t} {x} {k * q}))"
for op, u in (("sdot", 0), ("udot", 1)):
    for s, t, sz in (("s", 32, 2), ("d", 64, 3)):
        total = "d"
        for k in range(4):
            total = f"(add i{t} {total} (mul i{t} {quarter(t, 'a', k, not u)} {quarter(t, 'b', k, not u)}))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 68) (size {sz}) (zero 0) (op {u})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: Zda plus the dot product of each group of four {t // 4}-bit elements",
            f"(formal (vmap vni{t} ((d zd) (a zn) (b zm)) {total}))")
w("  ; --- CDOT: complex dot product, Zm rotated; CMLA: complex multiply-add -------")
for rot in (0, 90, 180, 270):
    for s, t, sz in (("s", 32, 2), ("d", 64, 3)):
        total = "d"
        for i in range(2):
            ar, ai = quarter(t, "a", 2 * i, True), quarter(t, "a", 2 * i + 1, True)
            br, bi = quarter(t, "b", 2 * i, True), quarter(t, "b", 2 * i + 1, True)
            m = lambda x, y: f"(mul i{t} {x} {y})"
            term = {0: f"(sub i{t} {m(ar, br)} {m(ai, bi)})", 90: f"(add i{t} {m(ar, bi)} {m(ai, br)})",
                    180: f"(add i{t} {m(ar, br)} {m(ai, bi)})", 270: f"(sub i{t} {m(ar, bi)} {m(ai, br)})"}[rot]
            total = f"(add i{t} {total} {term})"
        ins(f"cdot{rot}_{s}", f"CDOT{rot}_{s.upper()}", "SVE2_WIDE",
            f"(hi 68) (size {sz}) (zero 0) (op {4 + rot // 90})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"cdot{rot}_{s} $zd, $zn, $zm",
            f"CDOT #{rot}: Zda plus two complex products of {t // 4}-bit (real, imaginary) pairs, Zm rotated",
            f"(formal (vmap vni{t} ((d zd) (a zn) (b zm)) {total}))")
# CMLA: the even element is the real part of a pair and the odd the imaginary.
# By rotation, which part of Zn and which of Zm meet, and the sign:
#   0: re += n.re*m.re, im += n.re*m.im      90: re -= n.im*m.im, im += n.im*m.re
# 180: re -= n.re*m.re, im -= n.re*m.im     270: re += n.im*m.im, im -= n.im*m.re
for rot in (0, 90, 180, 270):
    for s, t, sz in SIZES:
        nre, nim = f"(vtrn1 vni{t} zn zn)", f"(vtrn2 vni{t} zn zn)"
        mre, mim = f"(vtrn1 vni{t} zm zm)", f"(vtrn2 vni{t} zm zm)"
        # At an even lane "same part" of Zm is its real part, at an odd lane
        # the imaginary; the swapped part is the other.
        same = f"(vmerge vni{t} {even(t)} {mre} {mim})"
        swap = f"(vmerge vni{t} {even(t)} {mim} {mre})"
        n, mm, sign_re, sign_im = {0: (nre, same, "+", "+"), 90: (nim, swap, "-", "+"),
                                   180: (nre, same, "-", "-"), 270: (nim, swap, "+", "-")}[rot]
        body = (f"(select i{t} (icmp_eq i{t} (and i{t} l 1) 0) "
                f"({'add' if sign_re == '+' else 'sub'} i{t} d (mul i{t} a b)) "
                f"({'add' if sign_im == '+' else 'sub'} i{t} d (mul i{t} a b)))")
        ins(f"cmla{rot}_{s}", f"CMLA{rot}_{s.upper()}", "SVE2_WIDE",
            f"(hi 68) (size {sz}) (zero 0) (op {8 + rot // 90})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"cmla{rot}_{s} $zd, $zn, $zm",
            f"CMLA #{rot}: Zda plus the complex product of {t}-bit (real, imaginary) pairs, Zm rotated",
            f"(formal (vmap vni{t} ((d zd) (a {n}) (b {mm}) (l (vid vni{t}))) {body}))")

# ---- the SVE2 remainder, integer (V6a) -----------------------------------------
w("  ; --- SQRDMLAH/SQRDMLSH: Zda plus or minus the rounding doubling high half ----")
# Arm saturates (Zda << T) +- 2*Zn*Zm + 2^(T-1), shifted right by T, once.
# Zda's part is an exact multiple of 2^T, so that is Zda plus Q -- the
# rounding doubling high half of +-Zn*Zm -- added with saturation. Q fits in
# T bits except for SQRDMLAH's MIN*MIN, where it is 2^(T-1): MAX unless Zda
# is negative, when Zda + 2^(T-1) fits.
def rdh(t, hi, lo):
    dhi = f"(or i{t} (shl i{t} {hi} 1) (lshr i{t} {lo} {t - 1}))"
    dlo = f"(shl i{t} {lo} 1)"
    nlo = f"(add i{t} {dlo} {1 << (t - 1)})"
    return f"(add i{t} {dhi} (select i{t} (icmp_ult i{t} {nlo} {dlo}) 1 0))"
for op, code in (("sqrdmlah", 28), ("sqrdmlsh", 29)):
    for s, t, sz in SIZES:
        hi, lo = f"(mulh i{t} a b)", f"(mul i{t} a b)"
        if op == "sqrdmlsh":
            hi, lo = (f"(add i{t} (xor i{t} {hi} {ALL8[t]}) (select i{t} (icmp_eq i{t} {lo} 0) 1 0))",
                      f"(sub i{t} 0 {lo})")
        q = rdh(t, hi, lo)
        value = f"(a64_sqadd_{t} d {q})"
        if op == "sqrdmlah":
            both_min = f"(and i{t} (icmp_eq i{t} a {MINV[t]}) (icmp_eq i{t} b {MINV[t]}))"
            value = (f"(select i{t} {both_min} (select i{t} (icmp_slt i{t} d 0) "
                     f"(add i{t} d {MINV[t]}) {MAXV[t]}) {value})")
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 68) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} inout) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: Zda {'plus' if op == 'sqrdmlah' else 'minus'} the rounding doubling high half "
            f"of each {t}-bit product, saturated", f"(formal (vmap vni{t} ((d zd) (a zn) (b zm)) {value}))")
w("  ; --- PMUL, PMULLB/T: carry-less multiply --------------------------------------")
def clmul(t, a, b, n):
    total = "0"
    for i in range(n):
        term = f"(select i{t} (icmp_ne i{t} (and i{t} {a} {1 << i}) 0) (shl i{t} {b} {i}) 0)"
        total = f"(xor i{t} {total} {term})"
    return total
ins("pmul", "PMUL", "SVE_INT_UNPRED", "(hi 4) (size 0) (one 1) (op 25)",
    "(zd vreg i8 out) (zn vreg i8 in) (zm vreg i8 in)", "pmul $zd, $zn, $zm",
    "PMUL: the low 8 bits of the carry-less product of each byte pair",
    f"(formal (vmap vni8 ((a zn) (b zm)) {clmul(8, 'a', 'b', 8)}))")
for op, code, top in (("pmullb", 26, 0), ("pmullt", 27, 1)):
    for s, t, sz in (("h", 16, 1), ("d", 64, 3)):
        n = t // 2
        half = (lambda x: f"(lshr i{t} {x} {n})") if top else (lambda x: f"(and i{t} {x} {(1 << n) - 1})")
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: the carry-less product of the {'odd' if top else 'even'} {n}-bit elements, at {t} bits",
            f"(formal (vmap vni{t} ((p {half('zn')}) (q {half('zm')})) {clmul(t, 'p', 'q', n)}))")
w("  ; --- SQDMLAL/SQDMLSL/SQDMULL, bottom and top: saturating doubling, long ------")
for base_op, hi, code0, kind in (("sqdmlal", 68, 24, "add"), ("sqdmlsl", 68, 26, "sub"), ("sqdmull", 69, 24, None)):
    for top in (0, 1):
        for s, t, sz in WIDE:
            n = t // 2
            half = (lambda x: f"(lshr i{t} {x} {n})") if top else (lambda x: x)
            a, b = f"(sext i{t} {n} {half('a')})", f"(sext i{t} {n} {half('b')})"
            product = f"(a64_sqadd_{t} (mul i{t} {a} {b}) (mul i{t} {a} {b}))"
            value = (product if kind is None else
                     f"(a64_sq{'add' if kind == 'add' else 'sub'}_{t} d {product})")
            name = f"{base_op}{'t' if top else 'b'}"
            binding = "((a zn) (b zm))" if kind is None else "((d zd) (a zn) (b zm))"
            dst = f"(zd vreg i{t} out)" if kind is None else f"(zd vreg i{t} inout)"
            ins(f"{name}_{s}", f"{name.upper()}_{s.upper()}", "SVE2_WIDE",
                f"(hi {hi}) (size {sz}) (zero 0) (op {code0 + top})",
                f"{dst} (zn vreg i{t} in) (zm vreg i{t} in)", f"{name}_{s} $zd, $zn, $zm",
                f"{name.upper()}: twice the product of the {'odd' if top else 'even'} {n}-bit elements, saturated"
                + ("" if kind is None else f", {'added to' if kind == 'add' else 'subtracted from'} Zda with saturation"),
                f"(formal (vmap vni{t} {binding} {value}))")
w("  ; --- SADDW/UADDW/SSUBW/USUBW: wide plus or minus a narrow half --------------")
for op, code, sign, arith, top in (("saddwb", 16, "s", "add", 0), ("saddwt", 17, "s", "add", 1),
                                   ("uaddwb", 18, "u", "add", 0), ("uaddwt", 19, "u", "add", 1),
                                   ("ssubwb", 20, "s", "sub", 0), ("ssubwt", 21, "s", "sub", 1),
                                   ("usubwb", 22, "u", "sub", 0), ("usubwt", 23, "u", "sub", 1)):
    for s, t, sz in WIDE:
        n = t // 2
        ext = "sext" if sign == "s" else "zext"
        b = f"({ext} i{t} {n} {'(lshr i' + str(t) + ' b ' + str(n) + ')' if top else 'b'})"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: each {t}-bit element of Zn {arith} the {'odd' if top else 'even'} {n}-bit element of Zm",
            f"(formal (vmap vni{t} ((a zn) (b zm)) ({arith} i{t} a {b})))")
w("  ; --- RADDHN/RSUBHN: the rounded high half, narrowed -----------------------------")
for op, code, arith, top in (("raddhnb", 26, "add", 0), ("raddhnt", 27, "add", 1),
                             ("rsubhnb", 30, "sub", 0), ("rsubhnt", 31, "sub", 1)):
    for s, t, sz in WIDE:
        n = t // 2
        value = narrow_put(t, n, f"(lshr i{t} (add i{t} ({arith} i{t} a b) {1 << (n - 1)}) {n})", top)
        dst = f"(zd vreg i{t} inout)" if top else f"(zd vreg i{t} out)"
        binding = "((a zn) (b zm) (d zd))" if top else "((a zn) (b zm))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 1) (op {code})",
            f"{dst} (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            f"{op.upper()}: the rounded high half of each {t}-bit {arith}, narrowed",
            f"(formal (vmap vni{t} {binding} {value}))")
w("  ; --- SADALP/UADALP: Zda plus the sum of each element's two halves ------------")
for op, code, sign in (("sadalp", 4, "s"), ("uadalp", 5, "u")):
    for s, t, sz in WIDE:
        n = t // 2
        ext = "sext" if sign == "s" else "zext"
        body = f"(add i{t} d (add i{t} ({ext} i{t} {n} a) ({ext} i{t} {n} (lshr i{t} a {n}))))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_UNARY", f"(hi 68) (size {sz}) (op {code}) (op2 5)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"{op}_{s} $zd, $pg, $zn",
            f"{op.upper()}: active {t}-bit elements of Zda plus both {n}-bit halves of Zn's",
            f"(formal (vmerge vni{t} {active(t)} (vmap vni{t} ((d zd) (a zn)) {body}) zd))")
w("  ; --- URECPE: Arm's unsigned reciprocal estimate, from the top nine bits ------")
# UnsignedRecipEstimate: all ones unless bit 31 is set; else nine bits from
# RecipEstimate(a), a the top nine bits: a = 2a + 1, b = 2^19 / a,
# r = (b + 1) / 2, placed at the top.
est = "(let ((a2 (add i32 (shl i32 (lshr i32 x 23) 1) 1)) (r (lshr i32 (add i32 (udiv i32 524288 a2) 1) 1))) (shl i32 (and i32 r 511) 23))"
ins("urecpe", "URECPE", "SVE_F_UNARY", "(hi 68) (size 2) (op 0) (op2 5)",
    "(zd vreg i32 inout) (pg preg i32 in) (zn vreg i32 in)", "urecpe $zd, $pg, $zn",
    "URECPE: Arm's unsigned reciprocal estimate of active 32-bit elements",
    f"(formal (vmerge vni32 {active(32)} (vmap vni32 ((x zn)) "
    f"(select i32 (icmp_slt i32 x 0) {est} 0xffffffff)) zd))")

# ---- the SVE2 remainder, floating point (V6b) -----------------------------------
w("  ; --- FCADD: complex add with Zm rotated, predicated ---------------------------")
for rot, opc in ((90, 0), (270, 1)):
    for s, t, sz in FSIZES:
        swapped = f"(vmerge vni{t} {even(t)} (vtrn2 vni{t} zm zm) (vtrn1 vni{t} zm zm))"
        sub_, add_ = f"(fsub vnf{t} zd {swapped})", f"(fadd vnf{t} zd {swapped})"
        value = (f"(vmerge vni{t} {even(t)} {sub_} {add_})" if rot == 90
                 else f"(vmerge vni{t} {even(t)} {add_} {sub_})")
        ins(f"fcadd{rot}_{s}", f"FCADD{rot}_{s.upper()}", "SVE_F_PRED",
            f"(hi 100) (size {sz}) (zero 0) (opc {opc}) (op 4)",
            f"(zd vreg i{t} inout) (pg preg i{t} in) (zm vreg i{t} in)", f"fcadd{rot}_{s} $zd, $pg, $zm",
            f"FCADD #{rot}: complex add of {t}-bit float (real, imaginary) pairs, Zm rotated; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value} zd))", latency=4)
w("  ; --- FCMLA: fused complex multiply-add, Zm rotated, predicated -------------")
for rot in (0, 90, 180, 270):
    for s, t, sz in FSIZES:
        nre, nim = f"(vtrn1 vni{t} zn zn)", f"(vtrn2 vni{t} zn zn)"
        mre, mim = f"(vtrn1 vni{t} zm zm)", f"(vtrn2 vni{t} zm zm)"
        same = f"(vmerge vni{t} {even(t)} {mre} {mim})"
        swap = f"(vmerge vni{t} {even(t)} {mim} {mre})"
        n, mm, neg_re, neg_im = {0: (nre, same, False, False), 90: (nim, swap, True, False),
                                 180: (nre, same, True, True), 270: (nim, swap, False, True)}[rot]
        m_signed = (f"(vmerge vni{t} {even(t)} {neg(t, mm) if neg_re else mm} "
                    f"{neg(t, mm) if neg_im else mm})")
        value = f"(fma vnf{t} {n} {m_signed} zda)"
        ins(f"fcmla{rot}_{s}", f"FCMLA{rot}_{s.upper()}", "SVE_F_MLA",
            f"(hi 100) (size {sz}) (one 0) (zero 0) (opc {rot // 90})",
            f"(zda vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in) (zm vreg i{t} in)",
            f"fcmla{rot}_{s} $zda, $pg, $zn, $zm",
            f"FCMLA #{rot}: Zda plus the fused complex product of {t}-bit float pairs, Zm rotated",
            f"(formal (vmerge vni{t} {active(t)} {value} zda))", latency=5)
w("  ; --- FADDP/FMAXNMP/FMINNMP/FMAXP/FMINP: pairwise, TRN1/TRN2 of (Zdn, Zm) ----")
for op, opc in (("faddp", 0), ("fmaxnmp", 4), ("fminnmp", 5), ("fmaxp", 6), ("fminp", 7)):
    for s, t, sz in FSIZES:
        a, b = f"(vtrn1 vni{t} zdn zm)", f"(vtrn2 vni{t} zdn zm)"
        value = f"(fadd vnf{t} {a} {b})" if op == "faddp" else fminmax(op[:-1], t, a, b)
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE_F_PRED",
            f"(hi 100) (size {sz}) (zero 1) (opc {opc}) (op 4)",
            f"(zd vreg i{t} out) (zdn vreg i{t} in (derive zd 0)) (pg preg i{t} in) (zm vreg i{t} in)",
            f"{op}_{s} $zd, $pg, $zm",
            f"{op.upper()}: adjacent float pairs of Zdn into the even elements, of Zm into the odd; inactive unchanged",
            f"(formal (vmerge vni{t} {active(t)} {value} zdn))", latency=4)
w("  ; --- FLOGB: the base-2 exponent of each float element, as a signed integer --")
FB = {16: (5, 10, 15), 32: (8, 23, 127), 64: (11, 52, 1023)}
for s, t, code in (("h", 16, 26), ("s", 32, 28), ("d", 64, 30)):
    e_bits, f_bits, bias = FB[t]
    e = f"(and i{t} (lshr i{t} x {f_bits}) {(1 << e_bits) - 1})"
    f = f"(and i{t} x {(1 << f_bits) - 1})"
    # A subnormal's exponent counts from its leading set bit.
    lead = "0"
    for i in range(f_bits):
        lead = f"(select i{t} (icmp_uge i{t} {f} {1 << i}) {i} {lead})"
    sub = f"(sub i{t} {lead} {bias + f_bits - 1})"
    value = (f"(select i{t} (icmp_eq i{t} {e} {(1 << e_bits) - 1}) "
             f"(select i{t} (icmp_eq i{t} {f} 0) {MAXV[t]} {MINV[t]}) "
             f"(select i{t} (icmp_eq i{t} {e} 0) (select i{t} (icmp_eq i{t} {f} 0) {MINV[t]} {sub}) "
             f"(sub i{t} {e} {bias})))")
    ins(f"flogb_{s}", f"FLOGB_{s.upper()}", "SVE_F_UNARY", f"(hi 101) (size 0) (op {code}) (op2 5)",
        f"(zd vreg i{t} inout) (pg preg i{t} in) (zn vreg i{t} in)", f"flogb_{s} $zd, $pg, $zn",
        f"FLOGB: the unbiased exponent of each active {t}-bit float; MIN for zero or NaN, MAX for infinity",
        f"(formal (vmerge vni{t} {active(t)} (vmap vni{t} ((x zn)) {value}) zd))", latency=3)
w("  ; --- FCVTNT/FCVTLT: to and from the top half; FCVTX/FCVTXNT: rounding to odd")
def to_odd(x):
    # Round to odd, single from double: nearest even when exact; else the
    # value truncated toward zero -- one unit back in magnitude where nearest
    # went up, which also brings an overflow to infinity back to the largest
    # finite -- with its lowest bit set. A NaN is the default NaN.
    r = f"(fcvt_f2f f32 64 {x})"
    back = f"(fcvt_f2f f64 32 {r})"
    up = (f"(fcmp_olt f64 (and i64 {x} 0x7fffffffffffffff) "
          f"(and i64 {back} 0x7fffffffffffffff))")
    truncated = f"(select i32 {up} (sub i32 {r} 1) {r})"
    return (f"(select i32 (fcmp_uno f64 {x} {x}) 0x7fc00000 "
            f"(select i32 (fcmp_oeq f64 {back} {x}) {r} (or i32 {truncated} 1)))")
CVT2 = (("fcvtnt_hs", 32, 2, 0x08, "(or i32 (shl i32 (zext i32 16 (fcvt_f2f f16 32 a)) 16) (and i32 d 0xffff))", True),
        ("fcvtnt_sd", 64, 3, 0x0a, "(or i64 (shl i64 (zext i64 32 (fcvt_f2f f32 64 a)) 32) (and i64 d 0xffffffff))", True),
        ("fcvtlt_sh", 32, 2, 0x09, "(zext i32 32 (fcvt_f2f f32 16 (lshr i32 a 16)))", False),
        ("fcvtlt_ds", 64, 3, 0x0b, "(fcvt_f2f f64 32 (lshr i64 a 32))", False))
for name, c, size, code, body, top in CVT2:
    binding = "((a zn) (d zd))" if top else "((a zn))"
    ins(name, name.upper(), "SVE_F_UNARY", f"(hi 100) (size {size}) (op {code}) (op2 5)",
        f"(zd vreg i{c} inout) (pg preg i{c} in) (zn vreg i{c} in)", f"{name} $zd, $pg, $zn",
        f"{name.split('_')[0].upper()}: {'into the top half of' if top else 'from the top half of'} each "
        f"active {c}-bit container", f"(formal (vmerge vni{c} {active(c)} (vmap vni{c} {binding} {body}) zd))",
        latency=4)
ins("fcvtx", "FCVTX", "SVE_F_UNARY", "(hi 101) (size 0) (op 10) (op2 5)",
    "(zd vreg i64 inout) (pg preg i64 in) (zn vreg i64 in)", "fcvtx $zd, $pg, $zn",
    "FCVTX: each active double to single precision, rounding to odd, in the low half of its container",
    f"(formal (vmerge vni64 {active(64)} (vmap vni64 ((a zn)) (zext i64 32 {to_odd('a')})) zd))", latency=4)
ins("fcvtxnt", "FCVTXNT", "SVE_F_UNARY", "(hi 100) (size 0) (op 10) (op2 5)",
    "(zd vreg i64 inout) (pg preg i64 in) (zn vreg i64 in)", "fcvtxnt $zd, $pg, $zn",
    "FCVTXNT: each active double to single precision, rounding to odd, into the top half of its container",
    f"(formal (vmerge vni64 {active(64)} (vmap vni64 ((a zn) (d zd)) "
    f"(or i64 (shl i64 (zext i64 32 {to_odd('a')}) 32) (and i64 d 0xffffffff))) zd))", latency=4)

# ---- the SVE2 optional extensions: BitPerm, AES, SHA3 (V6c) ---------------------
w("  ; --- BEXT/BDEP/BGRP: gather, scatter and group bits under a mask -------------")
# Bit i of the mask lands at (or comes from) the count of mask bits below it:
# one `cpop` per bit, so the description stays linear in the element.
def below(t, m, i):
    return f"(cpop i{t} (and i{t} {m} {(1 << i) - 1}))" if i else "0"
def bext(t, x, m):
    total = "0"
    for i in range(t):
        bit = f"(and i{t} (and i{t} (lshr i{t} {x} {i}) (lshr i{t} {m} {i})) 1)"
        total = f"(or i{t} {total} (shl i{t} {bit} {below(t, m, i)}))"
    return total
def bdep(t, x, m):
    total = "0"
    for i in range(t):
        bit = f"(and i{t} (and i{t} (lshr i{t} {m} {i}) (lshr i{t} {x} {below(t, m, i)})) 1)"
        total = f"(or i{t} {total} (shl i{t} {bit} {i}))"
    return total
for op, code in (("bext", 44), ("bdep", 45), ("bgrp", 46)):
    for s, t, sz in SIZES:
        if op == "bext":
            body = bext(t, "a", "m")
        elif op == "bdep":
            body = bdep(t, "a", "m")
        else:
            body = (f"(or i{t} {bext(t, 'a', 'm')} (shl i{t} {bext(t, 'a', 'n')} (cpop i{t} m)))")
        binding = "((a zn) (m zm))" if op != "bgrp" else f"((a zn) (m zm) (n (xor vni{t} zm {ALL8[t]})))"
        ins(f"{op}_{s}", f"{op.upper()}_{s.upper()}", "SVE2_WIDE", f"(hi 69) (size {sz}) (zero 0) (op {code})",
            f"(zd vreg i{t} out) (zn vreg i{t} in) (zm vreg i{t} in)", f"{op}_{s} $zd, $zn, $zm",
            {"bext": "BEXT: the bits of Zn under Zm's mask, packed at the bottom",
             "bdep": "BDEP: the low bits of Zn, scattered to the set bits of Zm's mask",
             "bgrp": "BGRP: Zn's bits under the mask packed at the bottom, the rest above them"}[op],
            f"(formal (vmap vni{t} {binding} {body}))", latency=3)

def aes_sbox():
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ (0x1b if a & 0x80 else 0)) & 0xff
            b >>= 1
        return r
    box = []
    for x in range(256):
        inv = next((y for y in range(256) if mul(x, y) == 1), 0)
        v = inv
        for k in range(1, 5):
            v ^= ((inv << k) | (inv >> (8 - k))) & 0xff
        box.append(v ^ 0x63)
    return box
SBOX = aes_sbox()
INV_SBOX = [SBOX.index(x) for x in range(256)]
def table(entries, x):
    # A byte's table entry as a decision tree on its bits: 255 tests, each
    # of the bound name alone.
    def node(lo, hi, bit):
        if hi - lo == 1:
            return str(entries[lo])
        mid = (lo + hi) // 2
        return f"(select i8 (icmp_ne i8 (and i8 {x} {1 << bit}) 0) {node(mid, hi, bit - 1)} {node(lo, mid, bit - 1)})"
    return node(0, 256, 7)
def shift_rows(src, inverse):
    # The AES state is column-major: byte i is row i & 3 of column i >> 2.
    # ShiftRows moves row r left by r columns, its inverse right -- a fixed
    # shuffle of each 128-bit segment.
    sign = -1 if inverse else 1
    ks = " ".join(str((i & 3) + 4 * (((i >> 2) + sign * (i & 3)) & 3)) for i in range(16))
    return f"(vsegperm vni8 {src} {ks})"
w("  ; --- AESE/AESD: round key, then (Inv)SubBytes and (Inv)ShiftRows ------------")
# SubBytes is bytewise, so it commutes with ShiftRows; applied first, the
# 256-entry S-box tree is built over two operands' bytes, and the shuffle after
# it reads exactly one of them per byte.
for op, code, box, inverse in (("aese", 56, SBOX, False), ("aesd", 57, INV_SBOX, True)):
    subbed = f"(vmap vni8 ((a (xor vni8 zdn zm))) {table(box, 'a')})"
    ins(op, op.upper(), "SVE2_CRYPTO", f"(hi {0x4522e000 >> 21}) (op 2) (op2 {code})",
        "(zd vreg i8 out) (zdn vreg i8 in (derive zd 0)) (zm vreg i8 in)", f"{op} $zd, $zm",
        f"{op.upper()}: each 128-bit segment XOR the round key, then {'InvSubBytes and InvShiftRows' if inverse else 'SubBytes and ShiftRows'}",
        f"(formal {shift_rows(subbed, inverse)})", latency=3)
w("  ; --- AESMC/AESIMC: (Inv)MixColumns over each 4-byte column ---------------------")
def xtime(x):
    return f"(xor i8 (shl i8 {x} 1) (select i8 (icmp_ne i8 (and i8 {x} 0x80) 0) 0x1b 0))"
def gmul(x, k):
    # x times a small constant in GF(2^8), by doubling.
    terms, power = [], x
    for bit in range(4):
        if k & (1 << bit):
            terms.append(power)
        power = xtime(power)
    total = terms[0]
    for term in terms[1:]:
        total = f"(xor i8 {total} {term})"
    return total
def column(k):
    # Byte (r + k) & 3 of this byte's column: a fixed shuffle too.
    ks = " ".join(str((i & ~3) | ((i + k) & 3)) for i in range(16))
    return f"(vsegperm vni8 zdn {ks})"
for op, code, coeffs in (("aesmc", 56, (2, 3, 1, 1)), ("aesimc", 57, (14, 11, 13, 9))):
    body = " ".join(f"(a{k} {column(k)})" for k in range(4))
    total = gmul("a0", coeffs[0])
    for k in range(1, 4):
        total = f"(xor i8 {total} {gmul(f'a{k}', coeffs[k])})"
    ins(op, op.upper(), "SVE2_CRYPTO_U", f"(hi {0x4520e000 >> 21}) (op 0) (op2 {code}) (zero 0)",
        "(zd vreg i8 out) (zdn vreg i8 in (derive zd 0))", f"{op} $zd",
        f"{op.upper()}: {'InvMixColumns' if op == 'aesimc' else 'MixColumns'} over each 4-byte column of the AES state",
        f"(formal (vmap vni8 ({body}) {total}))", latency=3)
w("  ; --- RAX1: Zn XOR Zm rotated left by one, over 64-bit elements --------------")
ins("rax1", "RAX1", "SVE2_RAX", f"(hi {0x4520f400 >> 21}) (op 61)",
    "(zd vreg i64 out) (zn vreg i64 in) (zm vreg i64 in)", "rax1 $zd, $zn, $zm",
    "RAX1: each 64-bit element of Zn XOR Zm's rotated left by one",
    "(formal (vmap vni64 ((a zn) (b zm)) (xor i64 a (or i64 (shl i64 b 1) (lshr i64 b 63)))))")

# ---- the FFR and the loads that write it (V3) ---------------------------------
# The FFR is the predicate every first-fault and non-fault load reads and
# clears; no instruction encodes it, so it is named as a fixed register -- the
# seventeenth of the predicate file. As Arm's model runs them:
#   - an element is suppressed when it, or an active element before it, would
#     fault; a suppressed element clears its FFR element and every one after;
#   - an element whose FFR element is already false is suppressed too, so a
#     loop's partly-cleared FFR carries into the next load;
#   - a suppressed element of Zt keeps what it held; an inactive one that is
#     not suppressed is zero, and an active one is loaded;
#   - LDFF1's first active element is an ordinary access: it faults, and is
#     never suppressed. Only the elements after it are first-fault.
FFR = "(ffr preg i{t} inout (fixed 16))"
w("  ; --- the FFR: SETFFR, WRFFR, RDFFR(S) ------------------------------------")
ins("setffr", "SETFFR", "SVE_FFR0", "(hi 623677440)", "(ffr preg i8 out (fixed 16))", "setffr",
    "Every FFR element true", "(formal (vdup vni8 1))")
ins("wrffr", "WRFFR", "SVE_FFR_N", "(hi 1217608) (lo 0)", "(ffr preg i8 out (fixed 16)) (pn preg i8 in)",
    "wrffr $pn", "The FFR from Pn", "(formal (and vni8 pn 1))")
ins("rdffr", "RDFFR", "SVE_FFR_D", "(hi 38903552)", "(pd preg i8 out) (ffr preg i8 in (fixed 16))",
    "rdffr $pd", "Pd from the FFR", "(formal (and vni8 ffr 1))")
rd = f"(and vni8 {active(8)} (and vni8 ffr 1))"
ins("rdffr_z", "RDFFR_Z", "SVE_FFR_GD", "(hi 1215608) (zero 0)",
    "(pd preg i8 out) (pg preg i8 in) (ffr preg i8 in (fixed 16))", "rdffr_z $pd, $pg",
    "Pd from the FFR where Pg is active, inactive zero", f"(formal {rd})")
ins("rdffrs_z", "RDFFRS_Z", "SVE_FFR_GD", "(hi 1223800) (zero 0)",
    "(pd preg i8 out) (pg preg i8 in) (ffr preg i8 in (fixed 16))", "rdffrs_z $pd, $pg",
    "RDFFR under Pg, and NZCV from the result",
    f"(behavior (set pd {rd}) {flags(8, rd, active(8))})")

def fault_load(t, address, first_fault):
    a = active(t)
    fault = f"(and vni{t} {a} (xor vni{t} (vinbounds vni{t} {address} mem_lo mem_hi) 1))"
    if first_fault:
        # The first active element is not first-fault: it faults for real.
        fault = f"(and vni{t} {fault} (xor vni{t} (vmsof vni{t} {a}) 1))"
    keep = f"(and vni{t} (and vni{t} ffr 1) (vmsbf vni{t} {fault}))"
    return (f"(behavior (when (ne (and vni{t} {keep} {a}) 0) (set zt (vload vni{t} {address}))) "
            f"(when (ne (and vni{t} {keep} (xor vni{t} {a} 1)) 0) (set zt 0)) "
            f"(set ffr (vmerge vni{t} {keep} ffr 0)))")

w("  ; --- LDNF1 [Xn, #imm, MUL VL] and LDFF1 [Xn, Xm, LSL #s], every size ------")
for s, t, sz in SIZES:
    dtype = LD[s][0]
    letter = "BHWD"["bhsd".index(s)]
    ins(f"ldnf1_{s}", f"LDNF1_{s.upper()}", "SVE_LD_SI", f"(hi 82) (dtype {dtype}) (nf 1) (op 5)",
        f"(zt vreg i{t} inout) (pg preg i{t} in) (rn a64_gpr64sp i64 in) (imm imm i4 in) {FFR.format(t=t)}",
        f"ldnf1_{s} $zt, $pg, $rn, $imm",
        f"LDNF1{letter}: a non-fault load from [Xn + imm * VL]; an element that would fault is "
        f"suppressed, and it and every element after keep Zt and clear the FFR",
        fault_load(t, base(), False), latency=4, category="custom")
    shift = f"(shl i64 rm {sz})" if sz else "rm"
    ins(f"ldff1_{s}", f"LDFF1_{s.upper()}", "SVE_LD_SS", f"(hi 82) (dtype {dtype}) (op 3)",
        f"(zt vreg i{t} inout) (pg preg i{t} in) (rn a64_gpr64sp i64 in) (rm a64_gpr64 i64 in) {FFR.format(t=t)}",
        f"ldff1_{s} $zt, $pg, $rn, $rm",
        f"LDFF1{letter}: a first-fault load from [Xn + (Xm << {sz})]; past the first active element, "
        f"an element that would fault is suppressed, and it and every element after keep Zt and "
        f"clear the FFR", fault_load(t, f"(add i64 rn {shift})", True), latency=4, category="custom")

w(")")
text = "\n".join(out) + "\n"
if len(sys.argv) < 2 or (sys.argv[1].startswith("-") and sys.argv[1] != "--check"):
    sys.exit(__doc__)
if sys.argv[1] == "--check":
    same = open(sys.argv[2]).read() == text
    print(f"{sys.argv[2]} == tools/gen_sve.py: {'PASS' if same else 'FAIL'}")
    sys.exit(0 if same else 1)
open(sys.argv[1], "w").write(text)
