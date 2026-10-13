#!/usr/bin/env python3
"""Compile and execute the generated C/Rust wide AArch64 executor ABIs."""

from __future__ import annotations

import argparse
import importlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
AXIS_FILE = AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl"


def emit(command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(AXIS_FILE), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def encode(entry: dict, **operands: int) -> int:
    word = entry["match"]
    for operand in entry["operands"]:
        if not operand["fields"]:
            continue
        value = operands[operand["name"]]
        for insn_lo, op_lo, width in operand["fields"]:
            mask = (1 << width) - 1
            word = (word & ~(mask << insn_lo)) | (
                ((value >> op_lo) & mask) << insn_lo
            )
    return word


def words(entries: dict[str, dict]) -> dict[str, int]:
    return {
        "add_x": encode(entries["ADD_X_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=0),
        "add_w": encode(entries["ADD_W_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=0),
        "sub_w": encode(entries["SUB_W_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=0),
        "add_x_lsr": encode(
            entries["ADD_X_SHIFT0"], rd=1, rn=2, rm=3, shift=1, imm6=4
        ),
        "sub_w_asr": encode(
            entries["SUB_W_SHIFT0"], rd=1, rn=2, rm=3, shift=2, imm6=31
        ),
        "adds_x_lsl63": encode(
            entries["ADDS_X_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=63
        ),
        "subs_w_lsr31": encode(
            entries["SUBS_W_SHIFT0"], rd=1, rn=2, rm=3, shift=1, imm6=31
        ),
        "reserved_add_x_shift": encode(
            entries["ADD_X_SHIFT0"], rd=1, rn=2, rm=3, shift=3, imm6=0
        ),
        "reserved_add_w_amount": encode(
            entries["ADD_W_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=32
        ),
        "add_x_ext_sp": encode(
            entries["ADD_X_EXT"], rd=31, rn=31, rm=2, option=0, imm3=4
        ),
        "sub_x_ext": encode(
            entries["SUB_X_EXT"], rd=1, rn=2, rm=3, option=6, imm3=2
        ),
        "adds_x_ext": encode(
            entries["ADDS_X_EXT"], rd=1, rn=2, rm=3, option=4, imm3=0
        ),
        "subs_w_ext": encode(
            entries["SUBS_W_EXT"], rd=1, rn=2, rm=3, option=2, imm3=4
        ),
        "reserved_add_x_ext": encode(
            entries["ADD_X_EXT"], rd=1, rn=2, rm=3, option=0, imm3=5
        ),
        "add_sp": encode(entries["ADD_X_IMM_SP"], rd=31, rn=31, imm=7, sh=0),
        "add_x_imm_sh12": encode(
            entries["ADD_X_IMM_SP"], rd=1, rn=2, imm=2, sh=1
        ),
        "sub_x_imm_sp": encode(
            entries["SUB_X_IMM_SP"], rd=31, rn=31, imm=1, sh=1
        ),
        "add_w_imm_sp": encode(
            entries["ADD_W_IMM_SP"], rd=31, rn=31, imm=1, sh=1
        ),
        "sub_w_imm": encode(
            entries["SUB_W_IMM_SP"], rd=1, rn=2, imm=1, sh=1
        ),
        "cmn_x_imm": encode(
            entries["ADDS_X_IMM"], rd=31, rn=2, imm=1, sh=0
        ),
        "cmp_sp_imm": encode(
            entries["SUBS_X_IMM"], rd=31, rn=31, imm=1, sh=1
        ),
        "adds_w_imm": encode(
            entries["ADDS_W_IMM"], rd=1, rn=2, imm=1, sh=0
        ),
        "subs_w_imm": encode(
            entries["SUBS_W_IMM"], rd=1, rn=2, imm=1, sh=0
        ),
        "adds_x": encode(entries["ADDS_X_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=0),
        "subs_w": encode(entries["SUBS_W_SHIFT0"], rd=1, rn=2, rm=3, shift=0, imm6=0),
        "b_eq": encode(entries["B_COND"], imm=3, cond=0),
        "ldr_u": encode(entries["LDR_X_UNSIGNED"], rt=1, rn=31, imm=2),
        "str_u": encode(entries["STR_X_UNSIGNED"], rt=2, rn=31, imm=1),
        "ldrb": encode(entries["LDRB_W_UNSIGNED"], rt=1, rn=31, imm=3),
        "ldrh": encode(entries["LDRH_W_UNSIGNED"], rt=1, rn=31, imm=2),
        "ldr_w": encode(entries["LDR_W_UNSIGNED"], rt=1, rn=31, imm=2),
        "ldrsb": encode(entries["LDRSB_X_UNSIGNED"], rt=1, rn=31, imm=4),
        "ldrsw": encode(entries["LDRSW_X_UNSIGNED"], rt=1, rn=31, imm=3),
        "strb": encode(entries["STRB_W_UNSIGNED"], rt=2, rn=31, imm=5),
        "strh": encode(entries["STRH_W_UNSIGNED"], rt=2, rn=31, imm=3),
        "str_w": encode(entries["STR_W_UNSIGNED"], rt=2, rn=31, imm=4),
        "accel_ldru8": encode(entries["ACCEL_LDRU8_32_U12"], rt=1, rn=2, imm=1),
        "accel_ldru16": encode(entries["ACCEL_LDRU16_32_U12"], rt=1, rn=2, imm=1),
        "accel_ldru32": encode(entries["ACCEL_LDRU32_U12"], rt=1, rn=2, imm=1),
        "accel_ldrs8": encode(entries["ACCEL_LDRS8_64_U12"], rt=1, rn=2, imm=1),
        "accel_ldrs32": encode(
            entries["ACCEL_LDRS32_64_U12"], rt=1, rn=2, imm=1
        ),
        "accel_str8": encode(entries["ACCEL_STR8_32_U12"], rt=1, rn=2, imm=1),
        "accel_str16": encode(entries["ACCEL_STR16_32_U12"], rt=1, rn=2, imm=1),
        "accel_str32": encode(entries["ACCEL_STR32_U12"], rt=1, rn=2, imm=1),
        "accel_ldr_reg": encode(
            entries["ACCEL_LDR64_REG_LSL3"], rt=1, rn=31, rm=31, option=3, s=1
        ),
        "accel_str_reg": encode(
            entries["ACCEL_STR64_REG_LSL3"], rt=31, rn=31, rm=5, option=3, s=1
        ),
        "accel_madd64": encode(entries["ACCEL_MADD64"], rd=1, rn=2, rm=3, ra=4),
        "accel_msub64": encode(entries["ACCEL_MSUB64"], rd=1, rn=2, rm=3, ra=4),
        "accel_madd32": encode(entries["ACCEL_MADD32"], rd=1, rn=2, rm=3, ra=4),
        "accel_msub32": encode(entries["ACCEL_MSUB32"], rd=1, rn=2, rm=3, ra=4),
        "accel_udiv64": encode(entries["ACCEL_UDIV64"], rd=1, rn=2, rm=3),
        "accel_sdiv64": encode(entries["ACCEL_SDIV64"], rd=1, rn=2, rm=3),
        "accel_udiv32": encode(entries["ACCEL_UDIV32"], rd=1, rn=2, rm=3),
        "accel_sdiv32": encode(entries["ACCEL_SDIV32"], rd=1, rn=2, rm=3),
        **{
            mnemonic.lower(): encode(
                entries[mnemonic], rd=1, rn=2, rm=3, cond=0
            )
            for mnemonic in [
                "ACCEL_CSEL64",
                "ACCEL_CSINC64",
                "ACCEL_CSINV64",
                "ACCEL_CSNEG64",
                "ACCEL_CSEL32",
                "ACCEL_CSINC32",
                "ACCEL_CSINV32",
                "ACCEL_CSNEG32",
            ]
        },
        **{
            mnemonic.lower(): encode(entries[mnemonic], rd=1, rn=2)
            for mnemonic in [
                "ACCEL_RBIT64",
                "ACCEL_REV16_64",
                "ACCEL_REV32_64",
                "ACCEL_REV64",
                "ACCEL_CLZ64",
                "ACCEL_CLS64",
                "ACCEL_RBIT32",
                "ACCEL_REV16_32",
                "ACCEL_REV32",
                "ACCEL_CLZ32",
                "ACCEL_CLS32",
            ]
        },
        "adcs_x_carry": encode(entries["ADCS_X"], rd=1, rn=2, rm=3),
        "sbcs_w_carry": encode(entries["SBCS_W"], rd=1, rn=2, rm=3),
        "accel_adcs64": encode(entries["ACCEL_ADCS64"], rd=1, rn=2, rm=3),
        "accel_sbcs32": encode(entries["ACCEL_SBCS32"], rd=1, rn=2, rm=3),
        "umulh_x": encode(entries["UMULH_X"], rd=1, rn=2, rm=3),
        "smulh_x": encode(entries["SMULH_X"], rd=1, rn=2, rm=3),
        "accel_umulh64": encode(entries["ACCEL_UMULH64"], rd=1, rn=2, rm=3),
        "accel_smulh64": encode(entries["ACCEL_SMULH64"], rd=1, rn=2, rm=3),
        "extr_x": encode(entries["EXTR_X"], rd=1, rn=2, rm=3, lsb=16),
        "extr_w_zero": encode(entries["EXTR_W"], rd=1, rn=2, rm=3, lsb=0),
        "accel_extr64": encode(entries["ACCEL_EXTR64"], rd=1, rn=2, rm=3, lsb=16),
        "accel_extr32_zero": encode(entries["ACCEL_EXTR32"], rd=1, rn=2, rm=3, lsb=0),
        "bic_x": encode(entries["BIC_X_SHIFTED"], rd=1, rn=2, rm=3, shift=1, imm=8),
        "accel_bic64": encode(entries["ACCEL_BIC64_SHIFTED"], rd=1, rn=2, rm=3, shift=1, amount=8),
        "bics_w": encode(entries["BICS_W_SHIFTED"], rd=1, rn=2, rm=3, shift=0, imm=0),
        "accel_bics32": encode(entries["ACCEL_BICS32_SHIFTED"], rd=1, rn=2, rm=3, shift=0, amount=0),
        "ccmp_x_reg": encode(entries["CCMP_X_REG"], rn=2, rhs=3, cond=0, literal=11),
        "accel_ccmp64_reg": encode(entries["ACCEL_CCMP64_REG"], rn=2, rhs=3, cond=0, literal=11),
        "ccmn_w_imm": encode(entries["CCMN_W_IMM"], rn=2, rhs=31, cond=0, literal=9),
        "accel_ccmn32_imm": encode(entries["ACCEL_CCMN32_IMM"], rn=2, rhs=31, cond=0, literal=9),
        "ldursb_x": encode(entries["LDURSB_X"], rt=1, rn=4, imm=(1 << 9) - 1),
        "accel_ldurs8_64_i9": encode(entries["ACCEL_LDURS8_64_I9"], rt=1, rn=4, imm=(1 << 9) - 1),
        "sturh_w": encode(entries["STURH_W"], rt=2, rn=4, imm=3),
        "accel_stur16_32_i9": encode(entries["ACCEL_STUR16_32_I9"], rt=2, rn=4, imm=3),
        "ldrsw_x_reg": encode(entries["LDRSW_X_REG"], rt=1, rn=4, rm=5, option=6, s=1),
        "accel_ldrs32_64_reg": encode(entries["ACCEL_LDRS32_64_REG"], rt=1, rn=4, rm=5, option=6, s=1),
        "strh_w_reg": encode(entries["STRH_W_REG"], rt=2, rn=4, rm=5, option=2, s=1),
        "accel_str16_32_reg": encode(entries["ACCEL_STR16_32_REG"], rt=2, rn=4, rm=5, option=2, s=1),
        "smaddl": encode(entries["SMADDL"], rd=1, rn=2, rm=3, ra=4),
        "umaddl": encode(entries["UMADDL"], rd=1, rn=2, rm=3, ra=4),
        "accel_smaddl": encode(entries["ACCEL_SMADDL"], rd=1, rn=2, rm=3, ra=4),
        "accel_umaddl": encode(entries["ACCEL_UMADDL"], rd=1, rn=2, rm=3, ra=4),
        "ldr_reg": encode(entries["LDR_X_REG_LSL3"], rt=1, rn=4, rm=5, option=3, s=1),
        "str_reg": encode(entries["STR_X_REG_LSL3"], rt=2, rn=4, rm=5, option=3, s=1),
        "ldr_post": encode(
            entries["LDR_X_POST"], rt=1, rn=4, imm=(1 << 9) - 8
        ),
        "ldr_pre": encode(
            entries["LDR_X_PRE"], rt=1, rn=4, imm=(1 << 9) - 8
        ),
        "accel_ldr_pre": encode(
            entries["ACCEL_LDR64_PRE_I9"], rt=1, rn=4, imm=(1 << 9) - 8
        ),
        "str_pre": encode(
            entries["STR_X_PRE"], rt=2, rn=4, imm=(1 << 9) - 16
        ),
        "str_post": encode(
            entries["STR_X_POST"], rt=2, rn=4, imm=(1 << 9) - 16
        ),
        "accel_str_post": encode(
            entries["ACCEL_STR64_POST_I9"], rt=2, rn=4, imm=(1 << 9) - 16
        ),
        "ldrsb_w_pre": encode(
            entries["LDRSB_W_PRE"], rt=1, rn=4, imm=(1 << 9) - 8
        ),
        "accel_ldrs8_32_pre": encode(
            entries["ACCEL_LDRS8_32_PRE_I9"], rt=1, rn=4, imm=(1 << 9) - 8
        ),
        "strh_w_post": encode(
            entries["STRH_W_POST"], rt=2, rn=4, imm=(1 << 9) - 16
        ),
        "accel_str16_32_post": encode(
            entries["ACCEL_STR16_32_POST_I9"], rt=2, rn=4, imm=(1 << 9) - 16
        ),
        "ldp_offset": encode(
            entries["LDP_X_OFFSET"], rt=1, rt2=2, rn=4, imm=2
        ),
        "stp_offset": encode(
            entries["STP_X_OFFSET"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "ldp_post": encode(
            entries["LDP_X_POST"], rt=1, rt2=2, rn=4, imm=2
        ),
        "stp_pre": encode(
            entries["STP_X_PRE"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "ldp_w_pre": encode(
            entries["LDP_W_PRE"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "accel_ldp32_pre": encode(
            entries["ACCEL_LDP32_PRE_I7"],
            rt=1,
            rt2=2,
            rn=4,
            imm=(1 << 7) - 2,
        ),
        "stp_w_post": encode(
            entries["STP_W_POST"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "accel_stp32_post": encode(
            entries["ACCEL_STP32_POST_I7"],
            rt=1,
            rt2=2,
            rn=4,
            imm=(1 << 7) - 2,
        ),
        "ldp_x_pre": encode(
            entries["LDP_X_PRE"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "accel_ldp64_pre": encode(
            entries["ACCEL_LDP64_PRE_I7"],
            rt=1,
            rt2=2,
            rn=4,
            imm=(1 << 7) - 2,
        ),
        "stp_x_post": encode(
            entries["STP_X_POST"], rt=1, rt2=2, rn=4, imm=(1 << 7) - 2
        ),
        "accel_stp64_post": encode(
            entries["ACCEL_STP64_POST_I7"],
            rt=1,
            rt2=2,
            rn=4,
            imm=(1 << 7) - 2,
        ),
        "ldxr_w": encode(entries["LDXR_W"], rt=1, rn=4),
        "ldxr_x": encode(entries["LDXR_X"], rt=1, rn=4),
        "stxr_w": encode(entries["STXR_W"], rs=3, rt=2, rn=4),
        "stxr_x": encode(entries["STXR_X"], rs=3, rt=2, rn=4),
        "accel_ldxr32": encode(entries["ACCEL_LDXR32"], rt=1, rn=4),
        "accel_ldxr64": encode(entries["ACCEL_LDXR64"], rt=1, rn=4),
        "accel_stxr32": encode(entries["ACCEL_STXR32"], rs=3, rt=2, rn=4),
        "accel_stxr64": encode(entries["ACCEL_STXR64"], rs=3, rt=2, rn=4),
        "ldaxr_x": encode(entries["LDAXR_X"], rt=1, rn=4),
        "stlxr_x": encode(entries["STLXR_X"], rs=3, rt=2, rn=4),
        "accel_ldaxr64": encode(entries["ACCEL_LDAXR64"], rt=1, rn=4),
        "accel_stlxr64": encode(entries["ACCEL_STLXR64"], rs=3, rt=2, rn=4),
        "ldxp_x": encode(entries["LDXP_X"], rt=1, rt2=2, rn=4),
        "stxp_x": encode(entries["STXP_X"], rs=3, rt=6, rt2=7, rn=4),
        "ldaxp_x": encode(entries["LDAXP_X"], rt=1, rt2=2, rn=4),
        "stlxp_x": encode(entries["STLXP_X"], rs=3, rt=6, rt2=7, rn=4),
        "accel_ldxp64": encode(entries["ACCEL_LDXP64"], rt=1, rt2=2, rn=4),
        "accel_stxp64": encode(
            entries["ACCEL_STXP64"], rs=3, rt=6, rt2=7, rn=4
        ),
        "accel_ldaxp64": encode(
            entries["ACCEL_LDAXP64"], rt=1, rt2=2, rn=4
        ),
        "accel_stlxp64": encode(
            entries["ACCEL_STLXP64"], rs=3, rt=6, rt2=7, rn=4
        ),
        "clrex": encode(entries["CLREX"], option=15),
        "accel_clrex": encode(entries["ACCEL_CLREX"], option=15),
        "dmb": encode(entries["DMB"], option=15),
        "dsb": encode(entries["DSB"], option=15),
        "isb": encode(entries["ISB"], option=15),
        "accel_dmb": encode(entries["ACCEL_DMB"], option=15),
        "accel_dsb": encode(entries["ACCEL_DSB"], option=15),
        "accel_isb": encode(entries["ACCEL_ISB"], option=15),
        "sb": encode(entries["SB"]),
        "csdb": encode(entries["CSDB"]),
        "ssbb": encode(entries["SSBB"]),
        "pssbb": encode(entries["PSSBB"]),
        "accel_sb": encode(entries["ACCEL_SB"]),
        "accel_csdb": encode(entries["ACCEL_CSDB"]),
        "accel_ssbb": encode(entries["ACCEL_SSBB"]),
        "accel_pssbb": encode(entries["ACCEL_PSSBB"]),
        "mrs_nzcv": encode(entries["MRS_NZCV"], rt=1),
        "msr_nzcv": encode(entries["MSR_NZCV"], rt=2),
        "accel_mrs_nzcv": encode(entries["ACCEL_MRS_NZCV"], rt=1),
        "accel_msr_nzcv": encode(entries["ACCEL_MSR_NZCV"], rt=2),
        "mrs_fpcr": encode(entries["MRS_FPCR"], rt=1),
        "msr_fpcr": encode(entries["MSR_FPCR"], rt=2),
        "mrs_fpsr": encode(entries["MRS_FPSR"], rt=1),
        "msr_fpsr": encode(entries["MSR_FPSR"], rt=2),
        "mrs_tpidr": encode(entries["MRS_TPIDR_EL0"], rt=1),
        "msr_tpidr": encode(entries["MSR_TPIDR_EL0"], rt=2),
        "mrs_tpidrro": encode(entries["MRS_TPIDRRO_EL0"], rt=1),
        "accel_mrs_fpcr": encode(entries["ACCEL_MRS_FPCR"], rt=1),
        "accel_msr_fpcr": encode(entries["ACCEL_MSR_FPCR"], rt=2),
        "accel_mrs_fpsr": encode(entries["ACCEL_MRS_FPSR"], rt=1),
        "accel_msr_fpsr": encode(entries["ACCEL_MSR_FPSR"], rt=2),
        "accel_mrs_tpidr": encode(entries["ACCEL_MRS_TPIDR_EL0"], rt=1),
        "accel_msr_tpidr": encode(entries["ACCEL_MSR_TPIDR_EL0"], rt=2),
        "accel_mrs_tpidrro": encode(entries["ACCEL_MRS_TPIDRRO_EL0"], rt=1),
        "ldarb_w": encode(entries["LDARB_W"], rt=1, rn=4),
        "stlrb_w": encode(entries["STLRB_W"], rt=2, rn=4),
        "ldar_x": encode(entries["LDAR_X"], rt=1, rn=4),
        "stlr_x": encode(entries["STLR_X"], rt=2, rn=4),
        "accel_ldar8": encode(entries["ACCEL_LDAR8"], rt=1, rn=4),
        "accel_stlr8": encode(entries["ACCEL_STLR8"], rt=2, rn=4),
        "accel_ldar64": encode(entries["ACCEL_LDAR64"], rt=1, rn=4),
        "accel_stlr64": encode(entries["ACCEL_STLR64"], rt=2, rn=4),
        "swp_x": encode(entries["SWP_X"], rs=1, rt=2, rn=4),
        "accel_swp64": encode(entries["ACCEL_SWP64"], rs=1, rt=2, rn=4),
        "swp_x_overlap": encode(entries["SWP_X"], rs=1, rt=1, rn=4),
        "accel_swp64_overlap": encode(entries["ACCEL_SWP64"], rs=1, rt=1, rn=4),
        "swpal_x": encode(entries["SWPAL_X"], rs=1, rt=2, rn=4),
        "accel_swpal64": encode(entries["ACCEL_SWPAL64"], rs=1, rt=2, rn=4),
        "swpalb": encode(entries["SWPALB"], rs=1, rt=2, rn=4),
        "accel_swpal8": encode(entries["ACCEL_SWPAL8"], rs=1, rt=2, rn=4),
        "swpalh": encode(entries["SWPALH"], rs=1, rt=2, rn=4),
        "accel_swpal16": encode(entries["ACCEL_SWPAL16"], rs=1, rt=2, rn=4),
        "ldaddalb": encode(entries["LDADDALB"], rs=1, rt=2, rn=4),
        "accel_ldaddal8": encode(entries["ACCEL_LDADDAL8"], rs=1, rt=2, rn=4),
        "ldaddalh": encode(entries["LDADDALH"], rs=1, rt=2, rn=4),
        "accel_ldaddal16": encode(entries["ACCEL_LDADDAL16"], rs=1, rt=2, rn=4),
        "ldclralb": encode(entries["LDCLRALB"], rs=1, rt=2, rn=4),
        "accel_ldclral8": encode(entries["ACCEL_LDCLRAL8"], rs=1, rt=2, rn=4),
        "ldclralh": encode(entries["LDCLRALH"], rs=1, rt=2, rn=4),
        "accel_ldclral16": encode(entries["ACCEL_LDCLRAL16"], rs=1, rt=2, rn=4),
        "ldeoralb": encode(entries["LDEORALB"], rs=1, rt=2, rn=4),
        "accel_ldeoral8": encode(entries["ACCEL_LDEORAL8"], rs=1, rt=2, rn=4),
        "ldeoralh": encode(entries["LDEORALH"], rs=1, rt=2, rn=4),
        "accel_ldeoral16": encode(entries["ACCEL_LDEORAL16"], rs=1, rt=2, rn=4),
        "ldsetalb": encode(entries["LDSETALB"], rs=1, rt=2, rn=4),
        "accel_ldsetal8": encode(entries["ACCEL_LDSETAL8"], rs=1, rt=2, rn=4),
        "ldsetalh": encode(entries["LDSETALH"], rs=1, rt=2, rn=4),
        "accel_ldsetal16": encode(entries["ACCEL_LDSETAL16"], rs=1, rt=2, rn=4),
        "ldsmaxal_x": encode(entries["LDSMAXAL_X"], rs=1, rt=2, rn=4),
        "accel_ldsminal8": encode(entries["ACCEL_LDSMINAL8"], rs=1, rt=2, rn=4),
        "ldumaxalh": encode(entries["LDUMAXALH"], rs=1, rt=2, rn=4),
        "accel_lduminal64": encode(entries["ACCEL_LDUMINAL64"], rs=1, rt=2, rn=4),
        "casal_x": encode(entries["CASAL_X"], rs=1, rt=2, rn=4),
        "accel_casal8": encode(entries["ACCEL_CASAL8"], rs=1, rt=2, rn=4),
        "caspal_x": encode(entries["CASPAL_X"], rs=2, rt=6, rn=4),
        "accel_caspal64": encode(entries["ACCEL_CASPAL64"], rs=2, rt=6, rn=4),
        "ldaddal_x": encode(entries["LDADDAL_X"], rs=1, rt=2, rn=4),
        "accel_ldaddal64": encode(entries["ACCEL_LDADDAL64"], rs=1, rt=2, rn=4),
        "ldadd_x_overlap": encode(entries["LDADD_X"], rs=1, rt=1, rn=4),
        "accel_ldadd64_overlap": encode(entries["ACCEL_LDADD64"], rs=1, rt=1, rn=4),
        "ldclral_x": encode(entries["LDCLRAL_X"], rs=1, rt=2, rn=4),
        "accel_ldclral64": encode(entries["ACCEL_LDCLRAL64"], rs=1, rt=2, rn=4),
        "ldeoral_x": encode(entries["LDEORAL_X"], rs=1, rt=2, rn=4),
        "accel_ldeoral64": encode(entries["ACCEL_LDEORAL64"], rs=1, rt=2, rn=4),
        "ldsetal_x": encode(entries["LDSETAL_X"], rs=1, rt=2, rn=4),
        "accel_ldsetal64": encode(entries["ACCEL_LDSETAL64"], rs=1, rt=2, rn=4),
        "adr": encode(entries["ADR"], rd=1, imm=0x12345),
        "adrp": encode(entries["ADRP"], rd=1, imm=2),
        "b_back": encode(entries["B"], imm=(1 << 26) - 1),
        "bl": encode(entries["BL"], imm=2),
        "br": encode(entries["BR"], rn=5),
        "ret": encode(entries["RET"], rn=30),
        "blr": encode(entries["BLR"], rn=30),
        "cbz_x": encode(entries["CBZ_X"], rt=1, imm=3),
        "cbnz_x": encode(entries["CBNZ_X"], rt=1, imm=(1 << 19) - 1),
        "cbz_w": encode(entries["CBZ_W"], rt=1, imm=2),
        "cbnz_w": encode(entries["CBNZ_W"], rt=1, imm=2),
        "tbz_w": encode(entries["TBZ_W"], rt=1, bit=5, imm=2),
        "tbnz_w": encode(
            entries["TBNZ_W"], rt=1, bit=5, imm=(1 << 14) - 1
        ),
        "tbz_x_high": encode(entries["TBZ_X_HIGH"], rt=1, bit=8, imm=2),
        "tbnz_x_high": encode(entries["TBNZ_X_HIGH"], rt=1, bit=8, imm=2),
        "and_x_shifted": encode(
            entries["AND_X_SHIFTED"], rd=1, rn=2, rm=3, shift=1, imm=56
        ),
        "orr_w_shifted": encode(
            entries["ORR_W_SHIFTED"], rd=1, rn=2, rm=3, shift=2, imm=28
        ),
        "ands_x_shifted": encode(
            entries["ANDS_X_SHIFTED"], rd=1, rn=2, rm=3, shift=0, imm=0
        ),
        "tst_x_shifted": encode(
            entries["ANDS_X_SHIFTED"], rd=31, rn=2, rm=3, shift=0, imm=0
        ),
        "ands_w_shifted": encode(
            entries["ANDS_W_SHIFTED"], rd=1, rn=2, rm=3, shift=0, imm=0
        ),
        **{
            mnemonic.lower(): encode(entries[mnemonic], rd=1, rn=2, rm=3)
            for mnemonic in [
                "LSLV_X",
                "LSRV_X",
                "ASRV_X",
                "RORV_X",
                "LSLV_W",
                "LSRV_W",
                "ASRV_W",
                "RORV_W",
            ]
        },
        "movn_x": encode(entries["MOVN_X"], rd=1, imm=0x1234, hw=1),
        "movz_x": encode(entries["MOVZ_X"], rd=1, imm=0xABCD, hw=2),
        "movk_x": encode(entries["MOVK_X"], rd=1, imm=0xABCD, hw=1),
        "and_x_imm": encode(
            entries["AND_X_IMM"], rd=1, rn=2, n=1, immr=0, imms=7
        ),
        "orr_x_imm": encode(
            entries["ORR_X_IMM"], rd=1, rn=2, n=0, immr=0, imms=54
        ),
        "eor_x_imm": encode(
            entries["EOR_X_IMM"], rd=1, rn=2, n=1, immr=8, imms=15
        ),
        "and_w_imm": encode(
            entries["AND_W_IMM"], rd=1, rn=2, immr=0, imms=7
        ),
        "orr_w_imm": encode(
            entries["ORR_W_IMM"], rd=1, rn=2, immr=0, imms=54
        ),
        "eor_w_imm": encode(
            entries["EOR_W_IMM"], rd=1, rn=2, immr=4, imms=51
        ),
        "tst_x_imm": encode(
            entries["ANDS_X_IMM"], rd=31, rn=2, n=1, immr=0, imms=7
        ),
        "ands_w_imm": encode(
            entries["ANDS_W_IMM"], rd=1, rn=2, immr=1, imms=0
        ),
        "reserved_x_n1": encode(
            entries["AND_X_IMM"], rd=1, rn=2, n=1, immr=0, imms=63
        ),
        "reserved_x_n0": encode(
            entries["AND_X_IMM"], rd=1, rn=2, n=0, immr=0, imms=63
        ),
        "reserved_w": encode(
            entries["AND_W_IMM"], rd=1, rn=2, immr=0, imms=31
        ),
        "reserved_sbfm_w_immr": encode(
            entries["SBFM_W"], rd=1, rn=2, immr=32, imms=0
        ),
        "reserved_ubfm_w_imms": encode(
            entries["UBFM_W"], rd=1, rn=2, immr=0, imms=32
        ),
        "ubfm_x": encode(entries["UBFM_X"], rd=1, rn=2, immr=8, imms=15),
        "sbfm_x": encode(entries["SBFM_X"], rd=1, rn=2, immr=8, imms=15),
        "bfm_x": encode(entries["BFM_X"], rd=1, rn=2, immr=56, imms=7),
        "ubfm_w": encode(entries["UBFM_W"], rd=1, rn=2, immr=8, imms=15),
        "sbfm_w": encode(entries["SBFM_W"], rd=1, rn=2, immr=8, imms=15),
        "bfm_w": encode(entries["BFM_W"], rd=1, rn=2, immr=24, imms=7),
    }


def c_driver(encoded: dict[str, int]) -> str:
    return f"""#include <stdint.h>
#include <stdio.h>
#include "axis_exec.h"

static int failures;
static int checks;
#define CHECK(label, condition) do {{ checks++; if (!(condition)) {{ printf("FAIL %s\\n", label); failures++; }} }} while (0)

typedef struct {{ uint64_t addr, value; uint32_t width; }} cell;
typedef struct {{ cell cells[128]; size_t count; }} memctx;
static uint64_t read64(void *ctx, uint64_t addr, uint32_t width) {{
  memctx *m = (memctx *)ctx;
  for (size_t i = 0; i < m->count; ++i) if (m->cells[i].addr == addr && m->cells[i].width == width) return m->cells[i].value;
  return 0;
}}
static void write64(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {{
  memctx *m = (memctx *)ctx;
  for (size_t i = 0; i < m->count; ++i) if (m->cells[i].addr == addr && m->cells[i].width == width) {{ m->cells[i].value = value; return; }}
  m->cells[m->count++] = (cell){{addr, value, width}};
}}

int main(void) {{
  uint64_t regs[32] = {{0}};
  axis_state64_entry entries[] = {{{{"sp", 10, 64}}, {{"nzcv", 0, 4}}, {{"exclusive_address", 0, 64}}, {{"exclusive_valid", 0, 1}}, {{"exclusive_size", 0, 8}}, {{"fpcr", 0, 32}}, {{"fpsr", 0, 32}}, {{"tpidr_el0", 0, 64}}, {{"tpidrro_el0", 0, 64}}}};
  axis_state64 state = {{entries, sizeof(entries) / sizeof(entries[0])}};
  axis_exec_result64 r;
  memctx memory = {{0}};
  axis_mem64 mem = {{read64, write64, &memory}};

  regs[2] = UINT64_MAX; regs[3] = 2;
  r = axis_exec_step64(0x{encoded["add_x"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD X", r.ok && r.result == 1 && regs[1] == 1);

  regs[2] = UINT64_C(0xffffffffffffffff); regs[3] = 2;
  r = axis_exec_step64(0x{encoded["add_w"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD W", r.ok && r.result == 1 && regs[1] == 1);
  regs[2] = 0; regs[3] = 1;
  r = axis_exec_step64(0x{encoded["sub_w"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUB W", r.ok && regs[1] == UINT64_C(0xffffffff));

  regs[2] = UINT64_C(0x10); regs[3] = UINT64_C(0x100);
  r = axis_exec_step64(0x{encoded["add_x_lsr"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD X LSR", r.ok && regs[1] == UINT64_C(0x20));
  regs[2] = 0; regs[3] = UINT64_C(0x80000000);
  r = axis_exec_step64(0x{encoded["sub_w_asr"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUB W ASR", r.ok && regs[1] == 1);
  entries[1].value = 0; regs[2] = 0; regs[3] = 1;
  r = axis_exec_step64(0x{encoded["adds_x_lsl63"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADDS X LSL 63", r.ok && regs[1] == UINT64_C(0x8000000000000000) && entries[1].value == 8);
  entries[1].value = 0; regs[2] = 0; regs[3] = UINT64_C(0x80000000);
  r = axis_exec_step64(0x{encoded["subs_w_lsr31"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUBS W LSR 31", r.ok && regs[1] == UINT64_C(0xffffffff) && entries[1].value == 8);
  r = axis_exec_step64(0x{encoded["reserved_add_x_shift"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C reserved ADD X shift", !r.ok);
  r = axis_exec_step64(0x{encoded["reserved_add_w_amount"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C reserved ADD W amount", !r.ok);

  entries[0].value = UINT64_C(0x100); regs[2] = UINT64_C(0xff);
  r = axis_exec_step64(0x{encoded["add_x_ext_sp"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD X extended SP", r.ok && entries[0].value == UINT64_C(0x10f0));
  regs[2] = 5; regs[3] = UINT64_C(0xffffffff);
  r = axis_exec_step64(0x{encoded["sub_x_ext"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUB X SXTW", r.ok && regs[1] == 9);
  entries[1].value = 0; regs[2] = 0; regs[3] = UINT64_C(0x80);
  r = axis_exec_step64(0x{encoded["adds_x_ext"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADDS X SXTB", r.ok && regs[1] == UINT64_C(0xffffffffffffff80) && entries[1].value == 8);
  entries[1].value = 0; regs[2] = 0; regs[3] = 1;
  r = axis_exec_step64(0x{encoded["subs_w_ext"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUBS W UXTW", r.ok && regs[1] == UINT64_C(0xfffffff0) && entries[1].value == 8);
  r = axis_exec_step64(0x{encoded["reserved_add_x_ext"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C reserved ADD X extended amount", !r.ok);

  entries[0].value = 10;
  r = axis_exec_step64(0x{encoded["add_sp"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SP", r.ok && axis_state64_read(&state, "sp") == 17);

  regs[2] = UINT64_C(0x1234);
  r = axis_exec_step64(0x{encoded["add_x_imm_sh12"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD X immediate shift 12", r.ok && regs[1] == UINT64_C(0x3234));
  entries[0].value = UINT64_C(0x5000);
  r = axis_exec_step64(0x{encoded["sub_x_imm_sp"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUB X immediate SP", r.ok && axis_state64_read(&state, "sp") == UINT64_C(0x4000));
  entries[0].value = UINT64_C(0xfffff000);
  r = axis_exec_step64(0x{encoded["add_w_imm_sp"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD W immediate WSP", r.ok && axis_state64_read(&state, "sp") == 0);
  /* The same instruction with bits above the view set in SP. W-SP is the low
     32 bits of the same register, so the upper half is neither read nor kept.
     Every other SP fixture holds a value that already fits in 32 bits, which
     makes a read that skips the view mask indistinguishable from one that
     applies it. */
  entries[0].value = UINT64_C(0xdeadbeef00000fff);
  r = axis_exec_step64(0x{encoded["add_w_imm_sp"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADD W immediate WSP ignores the upper half",
        r.ok && axis_state64_read(&state, "sp") == UINT64_C(0x1fff));
  regs[2] = UINT64_C(0x1000);
  r = axis_exec_step64(0x{encoded["sub_w_imm"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUB W immediate shift 12", r.ok && regs[1] == 0);
  regs[2] = UINT64_MAX; entries[1].value = 0;
  r = axis_exec_step64(0x{encoded["cmn_x_imm"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C CMN X immediate", r.ok && !r.wrote && entries[1].value == 6);
  entries[0].value = UINT64_C(0x1000); entries[1].value = 0;
  r = axis_exec_step64(0x{encoded["cmp_sp_imm"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C CMP SP immediate", r.ok && !r.wrote && entries[1].value == 6 && entries[0].value == UINT64_C(0x1000));
  regs[2] = UINT64_C(0x7fffffff); entries[1].value = 0;
  r = axis_exec_step64(0x{encoded["adds_w_imm"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADDS W immediate", r.ok && regs[1] == UINT64_C(0x80000000) && entries[1].value == 9);
  regs[2] = 0; entries[1].value = 0;
  r = axis_exec_step64(0x{encoded["subs_w_imm"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUBS W immediate", r.ok && regs[1] == UINT64_C(0xffffffff) && entries[1].value == 8);

  regs[2] = UINT64_C(0x7fffffffffffffff); regs[3] = 1;
  r = axis_exec_step64(0x{encoded["adds_x"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C ADDS NZCV", r.ok && regs[1] == UINT64_C(0x8000000000000000) && axis_state64_read(&state, "nzcv") == 9);

  regs[2] = UINT64_C(0x80000000); regs[3] = 1;
  r = axis_exec_step64(0x{encoded["subs_w"]:08x}u, "aarch64_base", regs, 32, NULL, 0, &state);
  CHECK("C SUBS W NZCV", r.ok && regs[1] == UINT64_C(0x7fffffff) && axis_state64_read(&state, "nzcv") == 3);

  axis_state64_write(&state, "nzcv", 4, 4);
  r = axis_exec_step64(0x{encoded["b_eq"]:08x}u, "aarch64_base", regs, 32, NULL, UINT64_C(0x1000), &state);
  CHECK("C B.cond", r.ok && r.next_pc == UINT64_C(0x100c));

  axis_state64_write(&state, "sp", UINT64_C(0x1000), 64);
  write64(&memory, UINT64_C(0x1010), UINT64_C(0x1122334455667788), 64);
  r = axis_exec_step64(0x{encoded["ldr_u"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDR unsigned SP", r.ok && regs[1] == UINT64_C(0x1122334455667788));

  regs[2] = UINT64_C(0x8877665544332211);
  r = axis_exec_step64(0x{encoded["str_u"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STR unsigned SP", r.ok && read64(&memory, UINT64_C(0x1008), 64) == regs[2]);

  write64(&memory, UINT64_C(0x1003), UINT64_C(0xab), 8);
  r = axis_exec_step64(0x{encoded["ldrb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRB zero extend", r.ok && regs[1] == UINT64_C(0xab));

  write64(&memory, UINT64_C(0x1004), UINT64_C(0xbeef), 16);
  r = axis_exec_step64(0x{encoded["ldrh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRH zero extend", r.ok && regs[1] == UINT64_C(0xbeef));

  write64(&memory, UINT64_C(0x1008), UINT64_C(0x89abcdef), 32);
  r = axis_exec_step64(0x{encoded["ldr_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDR W zero extend", r.ok && regs[1] == UINT64_C(0x89abcdef));

  write64(&memory, UINT64_C(0x1004), UINT64_C(0x80), 8);
  r = axis_exec_step64(0x{encoded["ldrsb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRSB sign extend", r.ok && regs[1] == UINT64_C(0xffffffffffffff80));

  write64(&memory, UINT64_C(0x100c), UINT64_C(0x80000001), 32);
  r = axis_exec_step64(0x{encoded["ldrsw"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRSW sign extend", r.ok && regs[1] == UINT64_C(0xffffffff80000001));

  regs[2] = UINT64_C(0x11223344556677a5);
  r = axis_exec_step64(0x{encoded["strb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STRB truncates", r.ok && read64(&memory, UINT64_C(0x1005), 8) == UINT64_C(0xa5));

  r = axis_exec_step64(0x{encoded["strh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STRH truncates", r.ok && read64(&memory, UINT64_C(0x1006), 16) == UINT64_C(0x77a5));

  r = axis_exec_step64(0x{encoded["str_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STR W truncates", r.ok && read64(&memory, UINT64_C(0x1010), 32) == UINT64_C(0x556677a5));

  regs[2] = UINT64_C(0x6000);
  write64(&memory, UINT64_C(0x6001), UINT64_C(0x80), 8);
  r = axis_exec_step64(0x{encoded["accel_ldru8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRU8", r.ok && regs[1] == UINT64_C(0x80));
  write64(&memory, UINT64_C(0x6002), UINT64_C(0x8001), 16);
  r = axis_exec_step64(0x{encoded["accel_ldru16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRU16", r.ok && regs[1] == UINT64_C(0x8001));
  write64(&memory, UINT64_C(0x6004), UINT64_C(0x80000001), 32);
  r = axis_exec_step64(0x{encoded["accel_ldru32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRU32", r.ok && regs[1] == UINT64_C(0x80000001));
  write64(&memory, UINT64_C(0x6001), UINT64_C(0x80), 8);
  r = axis_exec_step64(0x{encoded["accel_ldrs8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRS8", r.ok && regs[1] == UINT64_C(0xffffffffffffff80));
  write64(&memory, UINT64_C(0x6004), UINT64_C(0x80000001), 32);
  r = axis_exec_step64(0x{encoded["accel_ldrs32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRS32", r.ok && regs[1] == UINT64_C(0xffffffff80000001));
  regs[1] = UINT64_C(0x11223344556677a5);
  r = axis_exec_step64(0x{encoded["accel_str8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STR8", r.ok && read64(&memory, UINT64_C(0x6001), 8) == UINT64_C(0xa5));
  r = axis_exec_step64(0x{encoded["accel_str16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STR16", r.ok && read64(&memory, UINT64_C(0x6002), 16) == UINT64_C(0x77a5));
  r = axis_exec_step64(0x{encoded["accel_str32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STR32", r.ok && read64(&memory, UINT64_C(0x6004), 32) == UINT64_C(0x556677a5));
  axis_state64_write(&state, "sp", UINT64_C(0x6000), 64);
  write64(&memory, UINT64_C(0x6000), UINT64_C(0x8123456789abcdef), 64);
  r = axis_exec_step64(0x{encoded["accel_ldr_reg"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDR register SP/XZR", r.ok && regs[1] == UINT64_C(0x8123456789abcdef));
  regs[5] = 2;
  r = axis_exec_step64(0x{encoded["accel_str_reg"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STR register SP/XZR", r.ok && read64(&memory, UINT64_C(0x6010), 64) == 0);
  regs[2] = UINT64_MAX; regs[3] = 2; regs[4] = 3;
  r = axis_exec_step64(0x{encoded["accel_madd64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MADD64", r.ok && regs[1] == 1);
  r = axis_exec_step64(0x{encoded["accel_msub64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSUB64", r.ok && regs[1] == 5);
  regs[2] = UINT64_C(0xffffffff); regs[3] = 2; regs[4] = 3;
  r = axis_exec_step64(0x{encoded["accel_madd32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MADD32", r.ok && regs[1] == 1);
  r = axis_exec_step64(0x{encoded["accel_msub32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSUB32", r.ok && regs[1] == 5);
  regs[2] = 100; regs[3] = 0;
  r = axis_exec_step64(0x{encoded["accel_udiv64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator UDIV64 zero", r.ok && regs[1] == 0);
  regs[2] = UINT64_C(0xfffffffffffffff9); regs[3] = 3;
  r = axis_exec_step64(0x{encoded["accel_sdiv64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SDIV64 truncation", r.ok && regs[1] == UINT64_C(0xfffffffffffffffe));
  regs[2] = UINT64_C(0x8000000000000000); regs[3] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_sdiv64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SDIV64 overflow", r.ok && regs[1] == UINT64_C(0x8000000000000000));
  regs[2] = UINT64_C(0xffffffff); regs[3] = 3;
  r = axis_exec_step64(0x{encoded["accel_udiv32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator UDIV32", r.ok && regs[1] == UINT64_C(0x55555555));
  regs[2] = UINT64_C(0x80000000); regs[3] = UINT64_C(0xffffffff);
  r = axis_exec_step64(0x{encoded["accel_sdiv32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SDIV32 overflow", r.ok && regs[1] == UINT64_C(0x80000000));
  regs[2] = UINT64_C(0x0123456789abcdef); regs[3] = UINT64_C(0xfedcba9876543210);
  axis_state64_write(&state, "nzcv", 4, 4);
  r = axis_exec_step64(0x{encoded["accel_csel64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSEL64 true", r.ok && regs[1] == UINT64_C(0x0123456789abcdef));
  axis_state64_write(&state, "nzcv", 0, 4);
  r = axis_exec_step64(0x{encoded["accel_csinc64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSINC64 false", r.ok && regs[1] == UINT64_C(0xfedcba9876543211));
  r = axis_exec_step64(0x{encoded["accel_csinv64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSINV64 false", r.ok && regs[1] == UINT64_C(0x0123456789abcdef));
  r = axis_exec_step64(0x{encoded["accel_csneg64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSNEG64 false", r.ok && regs[1] == UINT64_C(0x0123456789abcdf0));
  r = axis_exec_step64(0x{encoded["accel_csel32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSEL32 false", r.ok && regs[1] == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_csinc32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSINC32 false", r.ok && regs[1] == UINT64_C(0x76543211));
  r = axis_exec_step64(0x{encoded["accel_csinv32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSINV32 false", r.ok && regs[1] == UINT64_C(0x89abcdef));
  r = axis_exec_step64(0x{encoded["accel_csneg32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSNEG32 false", r.ok && regs[1] == UINT64_C(0x89abcdf0));
  regs[2] = UINT64_C(0x0123456789abcdef);
  r = axis_exec_step64(0x{encoded["accel_rbit64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator RBIT64", r.ok && regs[1] == UINT64_C(0xf7b3d591e6a2c480));
  r = axis_exec_step64(0x{encoded["accel_rev16_64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator REV16_64", r.ok && regs[1] == UINT64_C(0x23016745ab89efcd));
  r = axis_exec_step64(0x{encoded["accel_rev32_64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator REV32_64", r.ok && regs[1] == UINT64_C(0x67452301efcdab89));
  r = axis_exec_step64(0x{encoded["accel_rev64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator REV64", r.ok && regs[1] == UINT64_C(0xefcdab8967452301));
  r = axis_exec_step64(0x{encoded["accel_clz64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLZ64", r.ok && regs[1] == 7);
  r = axis_exec_step64(0x{encoded["accel_cls64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLS64", r.ok && regs[1] == 6);
  r = axis_exec_step64(0x{encoded["accel_rbit32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator RBIT32", r.ok && regs[1] == UINT64_C(0xf7b3d591));
  r = axis_exec_step64(0x{encoded["accel_rev16_32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator REV16_32", r.ok && regs[1] == UINT64_C(0xab89efcd));
  r = axis_exec_step64(0x{encoded["accel_rev32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator REV32", r.ok && regs[1] == UINT64_C(0xefcdab89));
  r = axis_exec_step64(0x{encoded["accel_clz32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLZ32", r.ok && regs[1] == 0);
  r = axis_exec_step64(0x{encoded["accel_cls32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLS32", r.ok && regs[1] == 0);

  regs[2] = UINT64_MAX; regs[3] = 0; axis_state64_write(&state, "nzcv", 2, 4);
  r = axis_exec_step64(0x{encoded["adcs_x_carry"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ADCS X carry-out", r.ok && regs[1] == 0 && axis_state64_read(&state, "nzcv") == 6);
  regs[2] = 0; regs[3] = 0; axis_state64_write(&state, "nzcv", 0, 4);
  r = axis_exec_step64(0x{encoded["sbcs_w_carry"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SBCS W borrow", r.ok && regs[1] == UINT64_C(0xffffffff) && axis_state64_read(&state, "nzcv") == 8);
  regs[2] = UINT64_MAX; regs[3] = 0; axis_state64_write(&state, "nzcv", 2, 4);
  r = axis_exec_step64(0x{encoded["accel_adcs64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator ADCS64 carry-out", r.ok && regs[1] == 0 && axis_state64_read(&state, "nzcv") == 6);
  regs[2] = 0; regs[3] = 0; axis_state64_write(&state, "nzcv", 0, 4);
  r = axis_exec_step64(0x{encoded["accel_sbcs32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SBCS32 borrow", r.ok && regs[1] == UINT64_C(0xffffffff) && axis_state64_read(&state, "nzcv") == 8);
  regs[2] = UINT64_MAX; regs[3] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["umulh_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C UMULH X", r.ok && regs[1] == UINT64_C(0xfffffffffffffffe));
  r = axis_exec_step64(0x{encoded["accel_umulh64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator UMULH64", r.ok && regs[1] == UINT64_C(0xfffffffffffffffe));
  regs[2] = UINT64_C(0x8000000000000000); regs[3] = 2;
  r = axis_exec_step64(0x{encoded["smulh_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SMULH X", r.ok && regs[1] == UINT64_MAX);
  r = axis_exec_step64(0x{encoded["accel_smulh64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SMULH64", r.ok && regs[1] == UINT64_MAX);
  regs[2] = UINT64_C(0x0123456789abcdef); regs[3] = UINT64_C(0xfedcba9876543210);
  r = axis_exec_step64(0x{encoded["extr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C EXTR X asymmetric", r.ok && regs[1] == UINT64_C(0xcdeffedcba987654));
  r = axis_exec_step64(0x{encoded["accel_extr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator EXTR64", r.ok && regs[1] == UINT64_C(0xcdeffedcba987654));
  r = axis_exec_step64(0x{encoded["extr_w_zero"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C EXTR W zero", r.ok && regs[1] == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_extr32_zero"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator EXTR32 zero", r.ok && regs[1] == UINT64_C(0x76543210));
  regs[2] = UINT64_C(0xffff0000ffff0000); regs[3] = UINT64_C(0x00ff00ff00ff00ff);
  r = axis_exec_step64(0x{encoded["bic_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C BIC X inverted LSR", r.ok && regs[1] == UINT64_C(0xffff000000ff0000));
  r = axis_exec_step64(0x{encoded["accel_bic64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator BIC64", r.ok && regs[1] == UINT64_C(0xffff000000ff0000));
  regs[2] = UINT64_C(0x800000ff); regs[3] = UINT64_C(0x7fffffff); axis_state64_write(&state, "nzcv", 15, 4);
  r = axis_exec_step64(0x{encoded["bics_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C BICS W negative", r.ok && regs[1] == UINT64_C(0x80000000) && axis_state64_read(&state, "nzcv") == 8);
  axis_state64_write(&state, "nzcv", 15, 4);
  r = axis_exec_step64(0x{encoded["accel_bics32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator BICS32", r.ok && regs[1] == UINT64_C(0x80000000) && axis_state64_read(&state, "nzcv") == 8);
  regs[2] = 0; regs[3] = 1; axis_state64_write(&state, "nzcv", 4, 4);
  r = axis_exec_step64(0x{encoded["ccmp_x_reg"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CCMP X true flags", r.ok && axis_state64_read(&state, "nzcv") == 8);
  axis_state64_write(&state, "nzcv", 4, 4);
  r = axis_exec_step64(0x{encoded["accel_ccmp64_reg"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CCMP64 true flags", r.ok && axis_state64_read(&state, "nzcv") == 8);
  axis_state64_write(&state, "nzcv", 0, 4);
  r = axis_exec_step64(0x{encoded["ccmn_w_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CCMN W false literal", r.ok && axis_state64_read(&state, "nzcv") == 9);
  axis_state64_write(&state, "nzcv", 0, 4);
  r = axis_exec_step64(0x{encoded["accel_ccmn32_imm"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CCMN32 false literal", r.ok && axis_state64_read(&state, "nzcv") == 9);
  regs[4] = UINT64_C(0x9400); write64(&memory, UINT64_C(0x93ff), UINT64_C(0x80), 8);
  r = axis_exec_step64(0x{encoded["ldursb_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDURSB X negative offset", r.ok && regs[1] == UINT64_C(0xffffffffffffff80));
  r = axis_exec_step64(0x{encoded["accel_ldurs8_64_i9"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDURS8 X", r.ok && regs[1] == UINT64_C(0xffffffffffffff80));
  regs[2] = UINT64_C(0x11223344556677a5);
  r = axis_exec_step64(0x{encoded["sturh_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STURH W positive offset", r.ok && read64(&memory, UINT64_C(0x9403), 16) == UINT64_C(0x77a5));
  r = axis_exec_step64(0x{encoded["accel_stur16_32_i9"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STUR16", r.ok && read64(&memory, UINT64_C(0x9403), 16) == UINT64_C(0x77a5));
  regs[4] = UINT64_C(0x9600); regs[5] = UINT64_C(0xffffffff); write64(&memory, UINT64_C(0x95fc), UINT64_C(0x800000a5), 32);
  r = axis_exec_step64(0x{encoded["ldrsw_x_reg"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRSW SXTW scaled", r.ok && regs[1] == UINT64_C(0xffffffff800000a5));
  r = axis_exec_step64(0x{encoded["accel_ldrs32_64_reg"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRSW register", r.ok && regs[1] == UINT64_C(0xffffffff800000a5));
  regs[5] = 3; regs[2] = UINT64_C(0x11223344556677a5);
  r = axis_exec_step64(0x{encoded["strh_w_reg"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STRH UXTW scaled", r.ok && read64(&memory, UINT64_C(0x9606), 16) == UINT64_C(0x77a5));
  r = axis_exec_step64(0x{encoded["accel_str16_32_reg"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STRH register", r.ok && read64(&memory, UINT64_C(0x9606), 16) == UINT64_C(0x77a5));
  regs[2] = UINT64_C(0xaaaaaaaaffffffff); regs[3] = UINT64_C(0x5555555500000002); regs[4] = 7;
  r = axis_exec_step64(0x{encoded["smaddl"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SMADDL mixed width", r.ok && regs[1] == 5);
  r = axis_exec_step64(0x{encoded["accel_smaddl"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SMADDL", r.ok && regs[1] == 5);
  r = axis_exec_step64(0x{encoded["umaddl"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C UMADDL mixed width", r.ok && regs[1] == UINT64_C(0x200000005));
  r = axis_exec_step64(0x{encoded["accel_umaddl"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator UMADDL", r.ok && regs[1] == UINT64_C(0x200000005));

  regs[4] = UINT64_C(0x4000); regs[5] = 2;
  write64(&memory, UINT64_C(0x4010), UINT64_C(0x0102030405060708), 64);
  r = axis_exec_step64(0x{encoded["ldr_reg"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDR register offset", r.ok && regs[1] == UINT64_C(0x0102030405060708));

  regs[2] = UINT64_C(0x8877665544332211);
  r = axis_exec_step64(0x{encoded["str_reg"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STR register offset", r.ok && read64(&memory, UINT64_C(0x4010), 64) == regs[2]);

  regs[4] = UINT64_C(0x2000); write64(&memory, UINT64_C(0x2000), UINT64_C(0xaabbccddeeff0011), 64);
  r = axis_exec_step64(0x{encoded["ldr_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDR post-index", r.ok && regs[1] == UINT64_C(0xaabbccddeeff0011) && regs[4] == UINT64_C(0x1ff8));

  regs[4] = UINT64_C(0x2000); write64(&memory, UINT64_C(0x1ff8), UINT64_C(0x0123456789abcdef), 64);
  r = axis_exec_step64(0x{encoded["ldr_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDR pre-index", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[4] == UINT64_C(0x1ff8));
  regs[4] = UINT64_C(0x2000);
  r = axis_exec_step64(0x{encoded["accel_ldr_pre"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDR pre-index", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[4] == UINT64_C(0x1ff8));

  regs[4] = UINT64_C(0x3000); regs[2] = UINT64_C(0xfeedfacecafebeef);
  r = axis_exec_step64(0x{encoded["str_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STR pre-index", r.ok && regs[4] == UINT64_C(0x2ff0) && read64(&memory, UINT64_C(0x2ff0), 64) == regs[2]);

  regs[4] = UINT64_C(0x3000);
  r = axis_exec_step64(0x{encoded["str_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STR post-index", r.ok && regs[4] == UINT64_C(0x2ff0) && read64(&memory, UINT64_C(0x3000), 64) == regs[2]);
  regs[4] = UINT64_C(0x3000);
  r = axis_exec_step64(0x{encoded["accel_str_post"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STR post-index", r.ok && regs[4] == UINT64_C(0x2ff0) && read64(&memory, UINT64_C(0x3000), 64) == regs[2]);

  regs[4] = UINT64_C(0xc000); write64(&memory, UINT64_C(0xbff8), UINT64_C(0x80), 8);
  r = axis_exec_step64(0x{encoded["ldrsb_w_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDRSB W pre-index", r.ok && regs[1] == UINT64_C(0xffffff80) && regs[4] == UINT64_C(0xbff8));
  regs[4] = UINT64_C(0xc000);
  r = axis_exec_step64(0x{encoded["accel_ldrs8_32_pre"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDRSB W pre-index", r.ok && regs[1] == UINT64_C(0xffffff80) && regs[4] == UINT64_C(0xbff8));

  regs[2] = UINT64_C(0x11223344556677a5); regs[4] = UINT64_C(0xc200);
  r = axis_exec_step64(0x{encoded["strh_w_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STRH W post-index", r.ok && regs[4] == UINT64_C(0xc1f0) && read64(&memory, UINT64_C(0xc200), 16) == UINT64_C(0x77a5));
  regs[4] = UINT64_C(0xc200);
  r = axis_exec_step64(0x{encoded["accel_str16_32_post"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STRH W post-index", r.ok && regs[4] == UINT64_C(0xc1f0) && read64(&memory, UINT64_C(0xc200), 16) == UINT64_C(0x77a5));

  regs[4] = UINT64_C(0x5000);
  write64(&memory, UINT64_C(0x5010), UINT64_C(0x1111222233334444), 64);
  write64(&memory, UINT64_C(0x5018), UINT64_C(0x5555666677778888), 64);
  r = axis_exec_step64(0x{encoded["ldp_offset"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDP offset", r.ok && regs[1] == UINT64_C(0x1111222233334444) && regs[2] == UINT64_C(0x5555666677778888) && regs[4] == UINT64_C(0x5000));

  regs[1] = UINT64_C(0x9999aaaabbbbcccc); regs[2] = UINT64_C(0xddddeeeeffff0000); regs[4] = UINT64_C(0x6000);
  r = axis_exec_step64(0x{encoded["stp_offset"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STP offset", r.ok && read64(&memory, UINT64_C(0x5ff0), 64) == regs[1] && read64(&memory, UINT64_C(0x5ff8), 64) == regs[2] && regs[4] == UINT64_C(0x6000));

  regs[4] = UINT64_C(0x7000);
  write64(&memory, UINT64_C(0x7000), UINT64_C(0x0123456789abcdef), 64);
  write64(&memory, UINT64_C(0x7008), UINT64_C(0xfedcba9876543210), 64);
  r = axis_exec_step64(0x{encoded["ldp_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDP post-index", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[2] == UINT64_C(0xfedcba9876543210) && regs[4] == UINT64_C(0x7010));

  regs[1] = UINT64_C(0xcafebabedeadbeef); regs[2] = UINT64_C(0x1020304050607080); regs[4] = UINT64_C(0x8000);
  r = axis_exec_step64(0x{encoded["stp_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STP pre-index", r.ok && regs[4] == UINT64_C(0x7ff0) && read64(&memory, UINT64_C(0x7ff0), 64) == regs[1] && read64(&memory, UINT64_C(0x7ff8), 64) == regs[2]);

  write64(&memory, UINT64_C(0x8ff8), UINT64_C(0x89abcdef), 32);
  write64(&memory, UINT64_C(0x8ffc), UINT64_C(0xfedcba98), 32);
  regs[1] = UINT64_MAX; regs[2] = UINT64_MAX; regs[4] = UINT64_C(0x9000);
  r = axis_exec_step64(0x{encoded["ldp_w_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDP W pre-index", r.ok && regs[1] == UINT64_C(0x89abcdef) && regs[2] == UINT64_C(0xfedcba98) && regs[4] == UINT64_C(0x8ff8));
  regs[1] = UINT64_MAX; regs[2] = UINT64_MAX; regs[4] = UINT64_C(0x9000);
  r = axis_exec_step64(0x{encoded["accel_ldp32_pre"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDP W pre-index", r.ok && regs[1] == UINT64_C(0x89abcdef) && regs[2] == UINT64_C(0xfedcba98) && regs[4] == UINT64_C(0x8ff8));

  regs[1] = UINT64_C(0xaaaaaaaacafebabe); regs[2] = UINT64_C(0xbbbbbbbbdeadbeef); regs[4] = UINT64_C(0xa000);
  r = axis_exec_step64(0x{encoded["stp_w_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STP W post-index", r.ok && read64(&memory, UINT64_C(0xa000), 32) == UINT64_C(0xcafebabe) && read64(&memory, UINT64_C(0xa004), 32) == UINT64_C(0xdeadbeef) && regs[4] == UINT64_C(0x9ff8));
  regs[4] = UINT64_C(0xa000);
  r = axis_exec_step64(0x{encoded["accel_stp32_post"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STP W post-index", r.ok && read64(&memory, UINT64_C(0xa000), 32) == UINT64_C(0xcafebabe) && read64(&memory, UINT64_C(0xa004), 32) == UINT64_C(0xdeadbeef) && regs[4] == UINT64_C(0x9ff8));

  write64(&memory, UINT64_C(0xaff0), UINT64_C(0x0123456789abcdef), 64);
  write64(&memory, UINT64_C(0xaff8), UINT64_C(0xfedcba9876543210), 64);
  regs[4] = UINT64_C(0xb000);
  r = axis_exec_step64(0x{encoded["ldp_x_pre"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDP X pre-index", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[2] == UINT64_C(0xfedcba9876543210) && regs[4] == UINT64_C(0xaff0));
  regs[4] = UINT64_C(0xb000);
  r = axis_exec_step64(0x{encoded["accel_ldp64_pre"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDP X pre-index", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[2] == UINT64_C(0xfedcba9876543210) && regs[4] == UINT64_C(0xaff0));

  regs[1] = UINT64_C(0x1111222233334444); regs[2] = UINT64_C(0x5555666677778888); regs[4] = UINT64_C(0xc000);
  r = axis_exec_step64(0x{encoded["stp_x_post"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STP X post-index", r.ok && read64(&memory, UINT64_C(0xc000), 64) == regs[1] && read64(&memory, UINT64_C(0xc008), 64) == regs[2] && regs[4] == UINT64_C(0xbff0));
  regs[4] = UINT64_C(0xc000);
  r = axis_exec_step64(0x{encoded["accel_stp64_post"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STP X post-index", r.ok && read64(&memory, UINT64_C(0xc000), 64) == regs[1] && read64(&memory, UINT64_C(0xc008), 64) == regs[2] && regs[4] == UINT64_C(0xbff0));

  write64(&memory, UINT64_C(0xe000), UINT64_C(0x89abcdef), 32);
  regs[2] = UINT64_C(0xaaaaaaaacafebabe); regs[4] = UINT64_C(0xe000); entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["ldxr_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDXR W reservation", r.ok && regs[1] == UINT64_C(0x89abcdef) && entries[2].value == UINT64_C(0xe000) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["stxr_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STXR W success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe000), 32) == UINT64_C(0xcafebabe) && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe000), UINT64_C(0x76543210), 32);
  entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["accel_ldxr32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDXR W reservation", r.ok && regs[1] == UINT64_C(0x76543210) && entries[2].value == UINT64_C(0xe000) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_stxr32"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STXR W success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe000), 32) == UINT64_C(0xcafebabe) && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe100), UINT64_C(0x0123456789abcdef), 64);
  regs[2] = UINT64_C(0xcafebabedeadbeef); regs[4] = UINT64_C(0xe100); entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["ldxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDXR X reservation", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && entries[2].value == UINT64_C(0xe100) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["stxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STXR X success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe100), 64) == regs[2] && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe100), UINT64_C(0xfedcba9876543210), 64);
  entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["accel_ldxr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDXR X reservation", r.ok && regs[1] == UINT64_C(0xfedcba9876543210) && entries[2].value == UINT64_C(0xe100) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_stxr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STXR X success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe100), 64) == regs[2] && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe100), UINT64_C(0x1111222233334444), 64); entries[2].value = UINT64_C(0xe100); entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["stxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STXR invalid reservation", r.ok && regs[3] == 1 && read64(&memory, UINT64_C(0xe100), 64) == UINT64_C(0x1111222233334444));

  write64(&memory, UINT64_C(0xe200), UINT64_C(0x0123456789abcdef), 64); regs[2] = UINT64_C(0x8877665544332211); regs[4] = UINT64_C(0xe200); entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["ldaxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  r = axis_exec_step64(0x{encoded["stlxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDAXR/STLXR X", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[3] == 0 && read64(&memory, UINT64_C(0xe200), 64) == regs[2] && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe200), UINT64_C(0xfedcba9876543210), 64); entries[2].value = 0; entries[3].value = 0;
  r = axis_exec_step64(0x{encoded["accel_ldaxr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  r = axis_exec_step64(0x{encoded["accel_stlxr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDAXR/STLXR X", r.ok && regs[1] == UINT64_C(0xfedcba9876543210) && regs[3] == 0 && read64(&memory, UINT64_C(0xe200), 64) == regs[2] && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe280), UINT64_C(0x0123456789abcdef), 64);
  write64(&memory, UINT64_C(0xe288), UINT64_C(0xfedcba9876543210), 64);
  regs[4] = UINT64_C(0xe280); regs[6] = 19; regs[7] = 23; entries[2].value = 0; entries[3].value = 0; entries[4].value = 0;
  r = axis_exec_step64(0x{encoded["ldxp_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDXP X reservation", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && regs[2] == UINT64_C(0xfedcba9876543210) && entries[2].value == UINT64_C(0xe280) && entries[3].value == 1 && entries[4].value == 16);
  r = axis_exec_step64(0x{encoded["stxp_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STXP X pair success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe280), 64) == 19 && read64(&memory, UINT64_C(0xe288), 64) == 23 && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe280), 29, 64); write64(&memory, UINT64_C(0xe288), 31, 64);
  entries[2].value = UINT64_C(0xe280); entries[3].value = 1; entries[4].value = 8;
  r = axis_exec_step64(0x{encoded["stxp_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STXP X size mismatch is atomic", r.ok && regs[3] == 1 && read64(&memory, UINT64_C(0xe280), 64) == 29 && read64(&memory, UINT64_C(0xe288), 64) == 31 && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe280), 37, 64); write64(&memory, UINT64_C(0xe288), 41, 64);
  entries[2].value = 0; entries[3].value = 0; entries[4].value = 0;
  r = axis_exec_step64(0x{encoded["accel_ldaxp64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDAXP64 reservation", r.ok && regs[1] == 37 && regs[2] == 41 && entries[4].value == 16 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_stlxp64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STLXP64 pair success", r.ok && regs[3] == 0 && read64(&memory, UINT64_C(0xe280), 64) == 19 && read64(&memory, UINT64_C(0xe288), 64) == 23 && entries[3].value == 0);

  write64(&memory, UINT64_C(0xe2c0), 43, 64); regs[2] = 47; regs[4] = UINT64_C(0xe2c0);
  entries[2].value = UINT64_C(0xe2c0); entries[3].value = 1; entries[4].value = 8;
  r = axis_exec_step64(0x{encoded["clrex"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CLREX clears reservation", r.ok && entries[2].value == UINT64_C(0xe2c0) && entries[3].value == 0 && entries[4].value == 8);
  r = axis_exec_step64(0x{encoded["stxr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CLREX forces STXR failure", r.ok && regs[3] == 1 && read64(&memory, UINT64_C(0xe2c0), 64) == 43);

  entries[2].value = UINT64_C(0xe2c0); entries[3].value = 1; entries[4].value = 8;
  r = axis_exec_step64(0x{encoded["accel_clrex"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLREX clears reservation", r.ok && entries[2].value == UINT64_C(0xe2c0) && entries[3].value == 0 && entries[4].value == 8);
  r = axis_exec_step64(0x{encoded["accel_stxr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CLREX forces STXR failure", r.ok && regs[3] == 1 && read64(&memory, UINT64_C(0xe2c0), 64) == 43);

  entries[2].value = UINT64_C(0xe2c0); entries[3].value = 1; entries[4].value = 8; regs[1] = 53;
  r = axis_exec_step64(0x{encoded["dmb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C DMB barrier", r.ok && regs[1] == 53 && entries[2].value == UINT64_C(0xe2c0) && entries[3].value == 1 && entries[4].value == 8);
  r = axis_exec_step64(0x{encoded["dsb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C DSB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["isb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ISB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_dmb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator DMB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_dsb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator DSB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_isb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator ISB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["sb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["csdb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CSDB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["ssbb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SSBB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["pssbb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C PSSBB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_sb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_csdb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CSDB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_ssbb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SSBB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_pssbb"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator PSSBB barrier", r.ok && regs[1] == 53 && entries[3].value == 1);

  axis_state64_write(&state, "nzcv", 10, 4); regs[1] = 0;
  r = axis_exec_step64(0x{encoded["mrs_nzcv"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MRS NZCV", r.ok && regs[1] == UINT64_C(0xa0000000) && axis_state64_read(&state, "nzcv") == 10);
  regs[2] = UINT64_C(0x5123456789abcdef);
  r = axis_exec_step64(0x{encoded["msr_nzcv"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MSR NZCV", r.ok && axis_state64_read(&state, "nzcv") == 8);
  axis_state64_write(&state, "nzcv", 3, 4); regs[1] = 0;
  r = axis_exec_step64(0x{encoded["accel_mrs_nzcv"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MRS NZCV", r.ok && regs[1] == UINT64_C(0x30000000));
  regs[2] = UINT64_C(0xf0000000);
  r = axis_exec_step64(0x{encoded["accel_msr_nzcv"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSR NZCV", r.ok && axis_state64_read(&state, "nzcv") == 15);
  axis_state64_write(&state, "fpcr", UINT64_C(0x89abcdef), 32);
  r = axis_exec_step64(0x{encoded["mrs_fpcr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MRS FPCR", r.ok && regs[1] == UINT64_C(0x89abcdef));
  regs[2] = UINT64_C(0xfedcba9876543210);
  r = axis_exec_step64(0x{encoded["msr_fpcr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MSR FPCR truncates", r.ok && axis_state64_read(&state, "fpcr") == UINT64_C(0x76543210));
  axis_state64_write(&state, "fpsr", UINT64_C(0x12345678), 32);
  r = axis_exec_step64(0x{encoded["mrs_fpsr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MRS FPSR", r.ok && regs[1] == UINT64_C(0x12345678));
  r = axis_exec_step64(0x{encoded["msr_fpsr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MSR FPSR", r.ok && axis_state64_read(&state, "fpsr") == UINT64_C(0x76543210));
  axis_state64_write(&state, "tpidr_el0", UINT64_C(0x0123456789abcdef), 64);
  r = axis_exec_step64(0x{encoded["mrs_tpidr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MRS TPIDR_EL0", r.ok && regs[1] == UINT64_C(0x0123456789abcdef));
  r = axis_exec_step64(0x{encoded["msr_tpidr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MSR TPIDR_EL0", r.ok && axis_state64_read(&state, "tpidr_el0") == UINT64_C(0xfedcba9876543210));
  axis_state64_write(&state, "tpidrro_el0", UINT64_C(0xa5a5a5a55a5a5a5a), 64);
  r = axis_exec_step64(0x{encoded["mrs_tpidrro"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MRS TPIDRRO_EL0", r.ok && regs[1] == UINT64_C(0xa5a5a5a55a5a5a5a));
  r = axis_exec_step64(0x{encoded["accel_mrs_fpcr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MRS FPCR", r.ok && regs[1] == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_msr_fpcr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSR FPCR", r.ok && axis_state64_read(&state, "fpcr") == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_mrs_fpsr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MRS FPSR", r.ok && regs[1] == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_msr_fpsr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSR FPSR", r.ok && axis_state64_read(&state, "fpsr") == UINT64_C(0x76543210));
  r = axis_exec_step64(0x{encoded["accel_mrs_tpidr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MRS TPIDR_EL0", r.ok && regs[1] == UINT64_C(0xfedcba9876543210));
  r = axis_exec_step64(0x{encoded["accel_msr_tpidr"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MSR TPIDR_EL0", r.ok && axis_state64_read(&state, "tpidr_el0") == UINT64_C(0xfedcba9876543210));
  r = axis_exec_step64(0x{encoded["accel_mrs_tpidrro"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator MRS TPIDRRO_EL0", r.ok && regs[1] == UINT64_C(0xa5a5a5a55a5a5a5a));

  write64(&memory, UINT64_C(0xe2d0), UINT64_C(0xa5), 8); regs[2] = UINT64_C(0x1234); regs[4] = UINT64_C(0xe2d0); entries[3].value = 1;
  r = axis_exec_step64(0x{encoded["ldarb_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDARB", r.ok && regs[1] == UINT64_C(0xa5) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["stlrb_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STLRB", r.ok && read64(&memory, UINT64_C(0xe2d0), 8) == UINT64_C(0x34) && entries[3].value == 1);
  write64(&memory, UINT64_C(0xe2d0), UINT64_C(0x5a), 8);
  r = axis_exec_step64(0x{encoded["accel_ldar8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDAR8", r.ok && regs[1] == UINT64_C(0x5a) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_stlr8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STLR8", r.ok && read64(&memory, UINT64_C(0xe2d0), 8) == UINT64_C(0x34) && entries[3].value == 1);

  write64(&memory, UINT64_C(0xe2e0), UINT64_C(0x0123456789abcdef), 64); regs[2] = UINT64_C(0xfedcba9876543210); regs[4] = UINT64_C(0xe2e0);
  r = axis_exec_step64(0x{encoded["ldar_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDAR X", r.ok && regs[1] == UINT64_C(0x0123456789abcdef) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["stlr_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C STLR X", r.ok && read64(&memory, UINT64_C(0xe2e0), 64) == UINT64_C(0xfedcba9876543210) && entries[3].value == 1);
  write64(&memory, UINT64_C(0xe2e0), UINT64_C(0x1111222233334444), 64);
  r = axis_exec_step64(0x{encoded["accel_ldar64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDAR64", r.ok && regs[1] == UINT64_C(0x1111222233334444) && entries[3].value == 1);
  r = axis_exec_step64(0x{encoded["accel_stlr64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator STLR64", r.ok && read64(&memory, UINT64_C(0xe2e0), 64) == UINT64_C(0xfedcba9876543210) && entries[3].value == 1);

  write64(&memory, UINT64_C(0xe300), UINT64_C(0x0123456789abcdef), 64); regs[1] = UINT64_C(0x8877665544332211); regs[2] = 0; regs[4] = UINT64_C(0xe300);
  r = axis_exec_step64(0x{encoded["swp_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SWP X", r.ok && regs[2] == UINT64_C(0x0123456789abcdef) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0x8877665544332211));

  write64(&memory, UINT64_C(0xe300), UINT64_C(0xfedcba9876543210), 64); regs[1] = UINT64_C(0x1122334455667788); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_swp64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SWP X", r.ok && regs[2] == UINT64_C(0xfedcba9876543210) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0x1122334455667788));

  write64(&memory, UINT64_C(0xe300), UINT64_C(0x0102030405060708), 64); regs[1] = UINT64_C(0xa1a2a3a4a5a6a7a8);
  r = axis_exec_step64(0x{encoded["swp_x_overlap"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SWP X overlapping source/destination", r.ok && regs[1] == UINT64_C(0x0102030405060708) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0xa1a2a3a4a5a6a7a8));

  write64(&memory, UINT64_C(0xe300), UINT64_C(0x1112131415161718), 64); regs[1] = UINT64_C(0xb1b2b3b4b5b6b7b8);
  r = axis_exec_step64(0x{encoded["accel_swp64_overlap"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SWP X overlapping source/destination", r.ok && regs[1] == UINT64_C(0x1112131415161718) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0xb1b2b3b4b5b6b7b8));

  write64(&memory, UINT64_C(0xe300), UINT64_C(0x2122232425262728), 64); regs[1] = UINT64_C(0xc1c2c3c4c5c6c7c8); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["swpal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SWPAL X", r.ok && regs[2] == UINT64_C(0x2122232425262728) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0xc1c2c3c4c5c6c7c8));

  write64(&memory, UINT64_C(0xe300), UINT64_C(0x3132333435363738), 64); regs[1] = UINT64_C(0xd1d2d3d4d5d6d7d8); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_swpal64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SWPAL X", r.ok && regs[2] == UINT64_C(0x3132333435363738) && read64(&memory, UINT64_C(0xe300), 64) == UINT64_C(0xd1d2d3d4d5d6d7d8));

  write64(&memory, UINT64_C(0xe380), UINT64_C(0xa5), 8); regs[1] = UINT64_C(0x1234); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe380);
  r = axis_exec_step64(0x{encoded["swpalb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SWPALB", r.ok && regs[2] == UINT64_C(0xa5) && read64(&memory, UINT64_C(0xe380), 8) == UINT64_C(0x34));

  write64(&memory, UINT64_C(0xe380), UINT64_C(0x7e), 8); regs[1] = UINT64_C(0x1ff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_swpal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SWPAL8", r.ok && regs[2] == UINT64_C(0x7e) && read64(&memory, UINT64_C(0xe380), 8) == UINT64_C(0xff));

  write64(&memory, UINT64_C(0xe380), UINT64_C(0xbeef), 16); regs[1] = UINT64_C(0x12345678); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["swpalh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SWPALH", r.ok && regs[2] == UINT64_C(0xbeef) && read64(&memory, UINT64_C(0xe380), 16) == UINT64_C(0x5678));

  write64(&memory, UINT64_C(0xe380), UINT64_C(0x8001), 16); regs[1] = UINT64_C(0xffff0002); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_swpal16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator SWPAL16", r.ok && regs[2] == UINT64_C(0x8001) && read64(&memory, UINT64_C(0xe380), 16) == UINT64_C(0x0002));

  write64(&memory, UINT64_C(0xe3c0), UINT64_C(250), 8); regs[1] = UINT64_C(10); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe3c0);
  r = axis_exec_step64(0x{encoded["ldaddalb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDADDALB", r.ok && regs[2] == UINT64_C(250) && read64(&memory, UINT64_C(0xe3c0), 8) == UINT64_C(4));

  write64(&memory, UINT64_C(0xe3c0), UINT64_C(1), 8); regs[1] = UINT64_C(0x1ff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldaddal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDADDAL8", r.ok && regs[2] == UINT64_C(1) && read64(&memory, UINT64_C(0xe3c0), 8) == UINT64_C(0));

  write64(&memory, UINT64_C(0xe3c0), UINT64_C(0xfffe), 16); regs[1] = UINT64_C(5); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["ldaddalh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDADDALH", r.ok && regs[2] == UINT64_C(0xfffe) && read64(&memory, UINT64_C(0xe3c0), 16) == UINT64_C(3));

  write64(&memory, UINT64_C(0xe3c0), UINT64_C(0x8000), 16); regs[1] = UINT64_C(0x8001); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldaddal16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDADDAL16", r.ok && regs[2] == UINT64_C(0x8000) && read64(&memory, UINT64_C(0xe3c0), 16) == UINT64_C(1));

  write64(&memory, UINT64_C(0xe3d0), UINT64_C(0xf3), 8); regs[1] = UINT64_C(0x35); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe3d0);
  r = axis_exec_step64(0x{encoded["ldclralb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDCLRALB", r.ok && regs[2] == UINT64_C(0xf3) && read64(&memory, UINT64_C(0xe3d0), 8) == UINT64_C(0xc2));

  write64(&memory, UINT64_C(0xe3d0), UINT64_C(0xff), 8); regs[1] = UINT64_C(0x0f); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldclral8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDCLRAL8", r.ok && regs[2] == UINT64_C(0xff) && read64(&memory, UINT64_C(0xe3d0), 8) == UINT64_C(0xf0));

  write64(&memory, UINT64_C(0xe3d0), UINT64_C(0xf0ff), 16); regs[1] = UINT64_C(0x00f3); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["ldclralh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDCLRALH", r.ok && regs[2] == UINT64_C(0xf0ff) && read64(&memory, UINT64_C(0xe3d0), 16) == UINT64_C(0xf00c));

  write64(&memory, UINT64_C(0xe3d0), UINT64_C(0xffff), 16); regs[1] = UINT64_C(0xf0f0); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldclral16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDCLRAL16", r.ok && regs[2] == UINT64_C(0xffff) && read64(&memory, UINT64_C(0xe3d0), 16) == UINT64_C(0x0f0f));

  write64(&memory, UINT64_C(0xe3e0), UINT64_C(0xaa), 8); regs[1] = UINT64_C(0x0f); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe3e0);
  r = axis_exec_step64(0x{encoded["ldeoralb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDEORALB", r.ok && regs[2] == UINT64_C(0xaa) && read64(&memory, UINT64_C(0xe3e0), 8) == UINT64_C(0xa5));

  write64(&memory, UINT64_C(0xe3e0), UINT64_C(0xf0), 8); regs[1] = UINT64_C(0xff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldeoral8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDEORAL8", r.ok && regs[2] == UINT64_C(0xf0) && read64(&memory, UINT64_C(0xe3e0), 8) == UINT64_C(0x0f));

  write64(&memory, UINT64_C(0xe3e0), UINT64_C(0x55aa), 16); regs[1] = UINT64_C(0x0ff0); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["ldeoralh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDEORALH", r.ok && regs[2] == UINT64_C(0x55aa) && read64(&memory, UINT64_C(0xe3e0), 16) == UINT64_C(0x5a5a));

  write64(&memory, UINT64_C(0xe3e0), UINT64_C(0xaaaa), 16); regs[1] = UINT64_C(0xffff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldeoral16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDEORAL16", r.ok && regs[2] == UINT64_C(0xaaaa) && read64(&memory, UINT64_C(0xe3e0), 16) == UINT64_C(0x5555));

  write64(&memory, UINT64_C(0xe3f0), UINT64_C(0x10), 8); regs[1] = UINT64_C(0x81); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe3f0);
  r = axis_exec_step64(0x{encoded["ldsetalb"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDSETALB", r.ok && regs[2] == UINT64_C(0x10) && read64(&memory, UINT64_C(0xe3f0), 8) == UINT64_C(0x91));

  write64(&memory, UINT64_C(0xe3f0), UINT64_C(0), 8); regs[1] = UINT64_C(0xff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldsetal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDSETAL8", r.ok && regs[2] == UINT64_C(0) && read64(&memory, UINT64_C(0xe3f0), 8) == UINT64_C(0xff));

  write64(&memory, UINT64_C(0xe3f0), UINT64_C(0x1001), 16); regs[1] = UINT64_C(0x0ff0); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["ldsetalh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDSETALH", r.ok && regs[2] == UINT64_C(0x1001) && read64(&memory, UINT64_C(0xe3f0), 16) == UINT64_C(0x1ff1));

  write64(&memory, UINT64_C(0xe3f0), UINT64_C(0x8000), 16); regs[1] = UINT64_C(0x7fff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldsetal16"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDSETAL16", r.ok && regs[2] == UINT64_C(0x8000) && read64(&memory, UINT64_C(0xe3f0), 16) == UINT64_C(0xffff));

  write64(&memory, UINT64_C(0xe500), UINT64_C(0x8000000000000000), 64); regs[1] = UINT64_C(1); regs[2] = UINT64_MAX; regs[4] = UINT64_C(0xe500);
  r = axis_exec_step64(0x{encoded["ldsmaxal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDSMAXAL X signed", r.ok && regs[2] == UINT64_C(0x8000000000000000) && read64(&memory, UINT64_C(0xe500), 64) == UINT64_C(1));

  write64(&memory, UINT64_C(0xe500), UINT64_C(0x80), 8); regs[1] = UINT64_C(1); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_ldsminal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDSMINAL8 signed", r.ok && regs[2] == UINT64_C(0x80) && read64(&memory, UINT64_C(0xe500), 8) == UINT64_C(0x80));

  write64(&memory, UINT64_C(0xe500), UINT64_C(0x8000), 16); regs[1] = UINT64_C(0x7fff); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["ldumaxalh"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDUMAXALH unsigned", r.ok && regs[2] == UINT64_C(0x8000) && read64(&memory, UINT64_C(0xe500), 16) == UINT64_C(0x8000));

  write64(&memory, UINT64_C(0xe500), UINT64_C(0x8000000000000000), 64); regs[1] = UINT64_C(1); regs[2] = UINT64_MAX;
  r = axis_exec_step64(0x{encoded["accel_lduminal64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDUMINAL64 unsigned", r.ok && regs[2] == UINT64_C(0x8000000000000000) && read64(&memory, UINT64_C(0xe500), 64) == UINT64_C(1));

  write64(&memory, UINT64_C(0xe500), UINT64_C(7), 64); regs[1] = 7; regs[2] = 19; regs[4] = UINT64_C(0xe500);
  r = axis_exec_step64(0x{encoded["casal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CASAL X success", r.ok && regs[1] == 7 && read64(&memory, UINT64_C(0xe500), 64) == 19);
  write64(&memory, UINT64_C(0xe500), UINT64_C(11), 64); regs[1] = 7; regs[2] = 23;
  r = axis_exec_step64(0x{encoded["casal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CASAL X failure", r.ok && regs[1] == 11 && read64(&memory, UINT64_C(0xe500), 64) == 11);

  write64(&memory, UINT64_C(0xe500), UINT64_C(0xa5), 8); regs[1] = UINT64_C(0xffff00a5); regs[2] = UINT64_C(0x5a);
  r = axis_exec_step64(0x{encoded["accel_casal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CASAL8 success", r.ok && regs[1] == UINT64_C(0xa5) && read64(&memory, UINT64_C(0xe500), 8) == UINT64_C(0x5a));
  write64(&memory, UINT64_C(0xe500), UINT64_C(0xa5), 8); regs[1] = UINT64_C(0xa4); regs[2] = UINT64_C(0x33);
  r = axis_exec_step64(0x{encoded["accel_casal8"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CASAL8 failure", r.ok && regs[1] == UINT64_C(0xa5) && read64(&memory, UINT64_C(0xe500), 8) == UINT64_C(0xa5));

  write64(&memory, UINT64_C(0xe600), 7, 64); write64(&memory, UINT64_C(0xe608), 11, 64);
  regs[2] = 7; regs[3] = 11; regs[6] = 19; regs[7] = 23; regs[4] = UINT64_C(0xe600);
  r = axis_exec_step64(0x{encoded["caspal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CASPAL X pair success", r.ok && regs[2] == 7 && regs[3] == 11 && read64(&memory, UINT64_C(0xe600), 64) == 19 && read64(&memory, UINT64_C(0xe608), 64) == 23);
  write64(&memory, UINT64_C(0xe600), 29, 64); write64(&memory, UINT64_C(0xe608), 31, 64);
  regs[2] = 29; regs[3] = 37; regs[6] = 41; regs[7] = 43;
  r = axis_exec_step64(0x{encoded["caspal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C CASPAL X pair failure", r.ok && regs[2] == 29 && regs[3] == 31 && read64(&memory, UINT64_C(0xe600), 64) == 29 && read64(&memory, UINT64_C(0xe608), 64) == 31);

  write64(&memory, UINT64_C(0xe600), 47, 64); write64(&memory, UINT64_C(0xe608), 53, 64);
  regs[2] = 47; regs[3] = 53; regs[6] = 59; regs[7] = 61;
  r = axis_exec_step64(0x{encoded["accel_caspal64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator CASPAL64 pair success", r.ok && regs[2] == 47 && regs[3] == 53 && read64(&memory, UINT64_C(0xe600), 64) == 59 && read64(&memory, UINT64_C(0xe608), 64) == 61);

  write64(&memory, UINT64_C(0xe400), UINT64_C(7), 64); regs[1] = UINT64_C(5); regs[2] = 0; regs[4] = UINT64_C(0xe400);
  r = axis_exec_step64(0x{encoded["ldaddal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDADDAL X", r.ok && regs[2] == 7 && read64(&memory, UINT64_C(0xe400), 64) == 12);

  write64(&memory, UINT64_C(0xe400), UINT64_C(11), 64); regs[1] = UINT64_C(9); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_ldaddal64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDADDAL X", r.ok && regs[2] == 11 && read64(&memory, UINT64_C(0xe400), 64) == 20);

  write64(&memory, UINT64_C(0xe400), UINT64_C(13), 64); regs[1] = UINT64_C(6);
  r = axis_exec_step64(0x{encoded["ldadd_x_overlap"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDADD X overlapping source/destination", r.ok && regs[1] == 13 && read64(&memory, UINT64_C(0xe400), 64) == 19);

  write64(&memory, UINT64_C(0xe400), UINT64_C(17), 64); regs[1] = UINT64_C(8);
  r = axis_exec_step64(0x{encoded["accel_ldadd64_overlap"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDADD X overlapping source/destination", r.ok && regs[1] == 17 && read64(&memory, UINT64_C(0xe400), 64) == 25);

  write64(&memory, UINT64_C(0xe400), UINT64_C(0xff0f), 64); regs[1] = UINT64_C(0x0f0f); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["ldclral_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDCLRAL X", r.ok && regs[2] == UINT64_C(0xff0f) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0xf000));

  write64(&memory, UINT64_C(0xe400), UINT64_C(0xffff), 64); regs[1] = UINT64_C(0x00ff); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_ldclral64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDCLRAL X", r.ok && regs[2] == UINT64_C(0xffff) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0xff00));

  write64(&memory, UINT64_C(0xe400), UINT64_C(0xf0f0), 64); regs[1] = UINT64_C(0x0ff0); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["ldeoral_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDEORAL X", r.ok && regs[2] == UINT64_C(0xf0f0) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0xff00));

  write64(&memory, UINT64_C(0xe400), UINT64_C(0x0f0f), 64); regs[1] = UINT64_C(0x00ff); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_ldeoral64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDEORAL X", r.ok && regs[2] == UINT64_C(0x0f0f) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0x0ff0));

  write64(&memory, UINT64_C(0xe400), UINT64_C(0xf000), 64); regs[1] = UINT64_C(0x0f0f); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["ldsetal_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LDSETAL X", r.ok && regs[2] == UINT64_C(0xf000) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0xff0f));

  write64(&memory, UINT64_C(0xe400), UINT64_C(0x00f0), 64); regs[1] = UINT64_C(0x0f0f); regs[2] = 0;
  r = axis_exec_step64(0x{encoded["accel_ldsetal64"]:08x}u, "accelerator_scalar64", regs, 32, &mem, 0, &state);
  CHECK("C accelerator LDSETAL X", r.ok && regs[2] == UINT64_C(0x00f0) && read64(&memory, UINT64_C(0xe400), 64) == UINT64_C(0x0fff));

  r = axis_exec_step64(0x{encoded["adr"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0x1000), &state);
  CHECK("C ADR", r.ok && regs[1] == UINT64_C(0x13345));

  r = axis_exec_step64(0x{encoded["adrp"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0x12345), &state);
  CHECK("C ADRP", r.ok && regs[1] == UINT64_C(0x14000));

  r = axis_exec_step64(0x{encoded["b_back"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0x9000), &state);
  CHECK("C B backward", r.ok && r.next_pc == UINT64_C(0x8ffc));

  r = axis_exec_step64(0x{encoded["bl"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xa000), &state);
  CHECK("C BL link", r.ok && regs[30] == UINT64_C(0xa004) && r.next_pc == UINT64_C(0xa008) && r.wrote && r.dest == 30);

  regs[5] = UINT64_C(0xbeef0000);
  r = axis_exec_step64(0x{encoded["br"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xb000), &state);
  CHECK("C BR", r.ok && r.next_pc == UINT64_C(0xbeef0000));

  regs[30] = UINT64_C(0xcafe0000);
  r = axis_exec_step64(0x{encoded["ret"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xc000), &state);
  CHECK("C RET", r.ok && r.next_pc == UINT64_C(0xcafe0000));

  regs[30] = UINT64_C(0xd00d1000);
  r = axis_exec_step64(0x{encoded["blr"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xd100), &state);
  CHECK("C BLR X30 ordering", r.ok && r.next_pc == UINT64_C(0xd00d1000) && regs[30] == UINT64_C(0xd104));

  regs[1] = 0;
  r = axis_exec_step64(0x{encoded["cbz_x"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe000), &state);
  CHECK("C CBZ X", r.ok && r.next_pc == UINT64_C(0xe00c));

  regs[1] = 1;
  r = axis_exec_step64(0x{encoded["cbnz_x"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe000), &state);
  CHECK("C CBNZ X", r.ok && r.next_pc == UINT64_C(0xdffc));

  regs[1] = UINT64_C(0x100000000);
  r = axis_exec_step64(0x{encoded["cbz_w"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe100), &state);
  CHECK("C CBZ W", r.ok && r.next_pc == UINT64_C(0xe108));

  regs[1] = UINT64_C(0x100000001);
  r = axis_exec_step64(0x{encoded["cbnz_w"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe100), &state);
  CHECK("C CBNZ W", r.ok && r.next_pc == UINT64_C(0xe108));

  regs[1] = 0;
  r = axis_exec_step64(0x{encoded["tbz_w"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe200), &state);
  CHECK("C TBZ W", r.ok && r.next_pc == UINT64_C(0xe208));

  regs[1] = UINT64_C(1) << 5;
  r = axis_exec_step64(0x{encoded["tbnz_w"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe200), &state);
  CHECK("C TBNZ W", r.ok && r.next_pc == UINT64_C(0xe1fc));

  regs[1] = 0;
  r = axis_exec_step64(0x{encoded["tbz_x_high"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe300), &state);
  CHECK("C TBZ X high", r.ok && r.next_pc == UINT64_C(0xe308));

  regs[1] = UINT64_C(1) << 40;
  r = axis_exec_step64(0x{encoded["tbnz_x_high"]:08x}u, "aarch64_base", regs, 32, &mem, UINT64_C(0xe300), &state);
  CHECK("C TBNZ X high", r.ok && r.next_pc == UINT64_C(0xe308));

  regs[2] = UINT64_C(0xff); regs[3] = UINT64_C(0x8000000000000000);
  r = axis_exec_step64(0x{encoded["and_x_shifted"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C AND X shifted", r.ok && regs[1] == UINT64_C(0x80));

  regs[2] = 1; regs[3] = UINT64_C(0x80000000);
  r = axis_exec_step64(0x{encoded["orr_w_shifted"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ORR W shifted", r.ok && regs[1] == UINT64_C(0xfffffff9));

  regs[2] = UINT64_C(0x80000000000000ff); regs[3] = UINT64_C(0x8000000000000000); entries[1].value = 15;
  r = axis_exec_step64(0x{encoded["ands_x_shifted"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ANDS X flags", r.ok && regs[1] == UINT64_C(0x8000000000000000) && entries[1].value == 8);
  regs[2] = UINT64_C(0xf0); regs[3] = UINT64_C(0x0f); entries[1].value = 15;
  r = axis_exec_step64(0x{encoded["tst_x_shifted"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C TST X alias", r.ok && !r.wrote && entries[1].value == 4);
  regs[2] = UINT64_C(0xffffffff800000ff); regs[3] = UINT64_C(0x80000000); entries[1].value = 15;
  r = axis_exec_step64(0x{encoded["ands_w_shifted"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ANDS W flags", r.ok && regs[1] == UINT64_C(0x80000000) && entries[1].value == 8);

  regs[2] = UINT64_C(0x8000000000000001); regs[3] = 68;
  r = axis_exec_step64(0x{encoded["lslv_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LSLV X", r.ok && regs[1] == UINT64_C(0x10));
  r = axis_exec_step64(0x{encoded["lsrv_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LSRV X", r.ok && regs[1] == UINT64_C(0x0800000000000000));
  r = axis_exec_step64(0x{encoded["asrv_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ASRV X", r.ok && regs[1] == UINT64_C(0xf800000000000000));
  r = axis_exec_step64(0x{encoded["rorv_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C RORV X", r.ok && regs[1] == UINT64_C(0x1800000000000000));

  regs[2] = UINT64_C(0x80000001); regs[3] = 36;
  r = axis_exec_step64(0x{encoded["lslv_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LSLV W", r.ok && regs[1] == UINT64_C(0x10));
  r = axis_exec_step64(0x{encoded["lsrv_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C LSRV W", r.ok && regs[1] == UINT64_C(0x08000000));
  r = axis_exec_step64(0x{encoded["asrv_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ASRV W", r.ok && regs[1] == UINT64_C(0xf8000000));
  r = axis_exec_step64(0x{encoded["rorv_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C RORV W", r.ok && regs[1] == UINT64_C(0x18000000));

  r = axis_exec_step64(0x{encoded["movz_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MOVZ X", r.ok && regs[1] == UINT64_C(0x0000abcd00000000));
  r = axis_exec_step64(0x{encoded["movn_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MOVN X", r.ok && regs[1] == UINT64_C(0xffffffffedcbffff));
  regs[1] = UINT64_C(0x1122334455667788);
  r = axis_exec_step64(0x{encoded["movk_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C MOVK X", r.ok && regs[1] == UINT64_C(0x11223344abcd7788));

  regs[2] = UINT64_C(0x1234);
  r = axis_exec_step64(0x{encoded["and_x_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C AND X immediate", r.ok && regs[1] == UINT64_C(0x34));
  regs[2] = 0;
  r = axis_exec_step64(0x{encoded["orr_x_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ORR X immediate", r.ok && regs[1] == UINT64_C(0x7f7f7f7f7f7f7f7f));
  r = axis_exec_step64(0x{encoded["eor_x_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C EOR X immediate", r.ok && regs[1] == UINT64_C(0xff000000000000ff));

  regs[2] = UINT64_C(0x1234);
  r = axis_exec_step64(0x{encoded["and_w_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C AND W immediate", r.ok && regs[1] == UINT64_C(0x34));
  regs[2] = 0;
  r = axis_exec_step64(0x{encoded["orr_w_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ORR W immediate", r.ok && regs[1] == UINT64_C(0x7f7f7f7f));
  r = axis_exec_step64(0x{encoded["eor_w_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C EOR W immediate", r.ok && regs[1] == UINT64_C(0xf0f0f0f0));
  regs[2] = UINT64_C(0x100); entries[1].value = 15;
  r = axis_exec_step64(0x{encoded["tst_x_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C TST X immediate", r.ok && !r.wrote && entries[1].value == 4);
  regs[2] = UINT64_C(0x80000000); entries[1].value = 15;
  r = axis_exec_step64(0x{encoded["ands_w_imm"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C ANDS W immediate", r.ok && regs[1] == UINT64_C(0x80000000) && entries[1].value == 8);
  r = axis_exec_step64(0x{encoded["reserved_x_n1"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C reserved logical immediate X N=1", !r.ok);
  r = axis_exec_step64(0x{encoded["reserved_x_n0"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C reserved logical immediate X N=0", !r.ok);
  r = axis_exec_step64(0x{encoded["reserved_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C reserved logical immediate W", !r.ok);
  r = axis_exec_step64(0x{encoded["reserved_sbfm_w_immr"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C reserved SBFM W immr", !r.ok);
  r = axis_exec_step64(0x{encoded["reserved_ubfm_w_imms"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C reserved UBFM W imms", !r.ok);

  regs[2] = UINT64_C(0x12345678);
  r = axis_exec_step64(0x{encoded["ubfm_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C UBFM X", r.ok && regs[1] == UINT64_C(0x56));
  regs[2] = UINT64_C(0x8000);
  r = axis_exec_step64(0x{encoded["sbfm_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SBFM X", r.ok && regs[1] == UINT64_C(0xffffffffffffff80));
  regs[1] = UINT64_C(0x1122334455667788); regs[2] = UINT64_C(0xab);
  r = axis_exec_step64(0x{encoded["bfm_x"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C BFM X", r.ok && regs[1] == UINT64_C(0x112233445566ab88));

  regs[2] = UINT64_C(0x12345678);
  r = axis_exec_step64(0x{encoded["ubfm_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C UBFM W", r.ok && regs[1] == UINT64_C(0x56));
  regs[2] = UINT64_C(0x8000);
  r = axis_exec_step64(0x{encoded["sbfm_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C SBFM W", r.ok && regs[1] == UINT64_C(0xffffff80));
  regs[1] = UINT64_C(0x55667788); regs[2] = UINT64_C(0xab);
  r = axis_exec_step64(0x{encoded["bfm_w"]:08x}u, "aarch64_base", regs, 32, &mem, 0, &state);
  CHECK("C BFM W", r.ok && regs[1] == UINT64_C(0x5566ab88));

  printf("%d C wide-state checks, %d failures\\n", checks, failures);
  return failures ? 1 : 0;
}}
"""


def rust_driver(encoded: dict[str, int]) -> str:
    return f"""
#[derive(Default)]
struct TestMem {{ cells: Vec<(u64, u32, u64)> }}
impl Memory for TestMem {{
    fn read(&mut self, _addr: u32, _width: u32) -> u32 {{ 0 }}
    fn write(&mut self, _addr: u32, _value: u32, _width: u32) {{}}
}}
impl WideMemory for TestMem {{
    fn read64(&mut self, addr: u64, width: u32) -> u64 {{ self.cells.iter().find(|cell| cell.0 == addr && cell.1 == width).map_or(0, |cell| cell.2) }}
    fn write64(&mut self, addr: u64, value: u64, width: u32) {{
        if let Some(cell) = self.cells.iter_mut().find(|cell| cell.0 == addr && cell.1 == width) {{ cell.2 = value; }} else {{ self.cells.push((addr, width, value)); }}
    }}
}}

fn main() {{
    let mut failures = 0;
    let mut checks = 0;
    let mut regs = [0u64; 32];
    let mut state = [
        State64Entry {{ name: "sp", value: 10, width: 64 }},
        State64Entry {{ name: "nzcv", value: 0, width: 4 }},
        State64Entry {{ name: "exclusive_address", value: 0, width: 64 }},
        State64Entry {{ name: "exclusive_valid", value: 0, width: 1 }},
        State64Entry {{ name: "exclusive_size", value: 0, width: 8 }},
        State64Entry {{ name: "fpcr", value: 0, width: 32 }},
        State64Entry {{ name: "fpsr", value: 0, width: 32 }},
        State64Entry {{ name: "tpidr_el0", value: 0, width: 64 }},
        State64Entry {{ name: "tpidrro_el0", value: 0, width: 64 }},
    ];
    let mut mem = TestMem::default();

    regs[2] = u64::MAX; regs[3] = 2;
    let mut r = step64(0x{encoded["add_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.result == Some(1) && regs[1] == 1) {{ println!("FAIL Rust ADD X"); failures += 1; }}

    regs[2] = u64::MAX; regs[3] = 2;
    r = step64(0x{encoded["add_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.result == Some(1) && regs[1] == 1) {{ println!("FAIL Rust ADD W"); failures += 1; }}
    regs[2] = 0; regs[3] = 1;
    r = step64(0x{encoded["sub_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff) {{ println!("FAIL Rust SUB W"); failures += 1; }}

    regs[2] = 0x10; regs[3] = 0x100;
    r = step64(0x{encoded["add_x_lsr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x20) {{ println!("FAIL Rust ADD X LSR"); failures += 1; }}
    regs[2] = 0; regs[3] = 0x8000_0000;
    r = step64(0x{encoded["sub_w_asr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 1) {{ println!("FAIL Rust SUB W ASR"); failures += 1; }}
    state[1].value = 0; regs[2] = 0; regs[3] = 1;
    r = step64(0x{encoded["adds_x_lsl63"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000_0000_0000 && state[1].value == 8) {{ println!("FAIL Rust ADDS X LSL 63"); failures += 1; }}
    state[1].value = 0; regs[2] = 0; regs[3] = 0x8000_0000;
    r = step64(0x{encoded["subs_w_lsr31"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff && state[1].value == 8) {{ println!("FAIL Rust SUBS W LSR 31"); failures += 1; }}
    r = step64(0x{encoded["reserved_add_x_shift"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if r.ok {{ println!("FAIL Rust reserved ADD X shift"); failures += 1; }}
    r = step64(0x{encoded["reserved_add_w_amount"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if r.ok {{ println!("FAIL Rust reserved ADD W amount"); failures += 1; }}

    state[0].value = 0x100; regs[2] = 0xff;
    r = step64(0x{encoded["add_x_ext_sp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state[0].value == 0x10f0) {{ println!("FAIL Rust ADD X extended SP"); failures += 1; }}
    regs[2] = 5; regs[3] = 0xffff_ffff;
    r = step64(0x{encoded["sub_x_ext"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 9) {{ println!("FAIL Rust SUB X SXTW"); failures += 1; }}
    state[1].value = 0; regs[2] = 0; regs[3] = 0x80;
    r = step64(0x{encoded["adds_x_ext"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80 && state[1].value == 8) {{ println!("FAIL Rust ADDS X SXTB"); failures += 1; }}
    state[1].value = 0; regs[2] = 0; regs[3] = 1;
    r = step64(0x{encoded["subs_w_ext"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_fff0 && state[1].value == 8) {{ println!("FAIL Rust SUBS W UXTW"); failures += 1; }}
    r = step64(0x{encoded["reserved_add_x_ext"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if r.ok {{ println!("FAIL Rust reserved ADD X extended amount"); failures += 1; }}

    state[0].value = 10;
    r = step64(0x{encoded["add_sp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "sp") == 17) {{ println!("FAIL Rust SP"); failures += 1; }}

    regs[2] = 0x1234;
    r = step64(0x{encoded["add_x_imm_sh12"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x3234) {{ println!("FAIL Rust ADD X immediate shift 12"); failures += 1; }}
    state[0].value = 0x5000;
    r = step64(0x{encoded["sub_x_imm_sp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "sp") == 0x4000) {{ println!("FAIL Rust SUB X immediate SP"); failures += 1; }}
    state[0].value = 0xffff_f000;
    r = step64(0x{encoded["add_w_imm_sp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "sp") == 0) {{ println!("FAIL Rust ADD W immediate WSP"); failures += 1; }}
    state[0].value = 0xdead_beef_0000_0fff;
    r = step64(0x{encoded["add_w_imm_sp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "sp") == 0x1fff) {{ println!("FAIL Rust ADD W immediate WSP upper half"); failures += 1; }}
    regs[2] = 0x1000;
    r = step64(0x{encoded["sub_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0) {{ println!("FAIL Rust SUB W immediate shift 12"); failures += 1; }}
    regs[2] = u64::MAX; state[1].value = 0;
    r = step64(0x{encoded["cmn_x_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.wrote.is_none() && state64_read(&state, "nzcv") == 6) {{ println!("FAIL Rust CMN X immediate"); failures += 1; }}
    state[0].value = 0x1000; state[1].value = 0;
    r = step64(0x{encoded["cmp_sp_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.wrote.is_none() && state64_read(&state, "nzcv") == 6 && state64_read(&state, "sp") == 0x1000) {{ println!("FAIL Rust CMP SP immediate"); failures += 1; }}
    regs[2] = 0x7fff_ffff; state[1].value = 0;
    r = step64(0x{encoded["adds_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000 && state64_read(&state, "nzcv") == 9) {{ println!("FAIL Rust ADDS W immediate"); failures += 1; }}
    regs[2] = 0; state[1].value = 0;
    r = step64(0x{encoded["subs_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust SUBS W immediate"); failures += 1; }}

    regs[2] = 0x7fff_ffff_ffff_ffff; regs[3] = 1;
    r = step64(0x{encoded["adds_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000_0000_0000 && state64_read(&state, "nzcv") == 9) {{ println!("FAIL Rust ADDS NZCV"); failures += 1; }}

    regs[2] = 0x8000_0000; regs[3] = 1;
    r = step64(0x{encoded["subs_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7fff_ffff && state64_read(&state, "nzcv") == 3) {{ println!("FAIL Rust SUBS W NZCV"); failures += 1; }}

    state64_write(&mut state, "nzcv", 4, 4);
    r = step64(0x{encoded["b_eq"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0x1000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0x100c) {{ println!("FAIL Rust B.cond"); failures += 1; }}

    state64_write(&mut state, "sp", 0x1000, 64);
    mem.write64(0x1010, 0x1122_3344_5566_7788, 64);
    r = step64(0x{encoded["ldr_u"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1122_3344_5566_7788) {{ println!("FAIL Rust LDR unsigned SP"); failures += 1; }}

    regs[2] = 0x8877_6655_4433_2211;
    r = step64(0x{encoded["str_u"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x1008, 64) == regs[2]) {{ println!("FAIL Rust STR unsigned SP"); failures += 1; }}

    mem.write64(0x1003, 0xab, 8);
    r = step64(0x{encoded["ldrb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xab) {{ println!("FAIL Rust LDRB zero extend"); failures += 1; }}

    mem.write64(0x1004, 0xbeef, 16);
    r = step64(0x{encoded["ldrh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xbeef) {{ println!("FAIL Rust LDRH zero extend"); failures += 1; }}

    mem.write64(0x1008, 0x89ab_cdef, 32);
    r = step64(0x{encoded["ldr_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef) {{ println!("FAIL Rust LDR W zero extend"); failures += 1; }}

    mem.write64(0x1004, 0x80, 8);
    r = step64(0x{encoded["ldrsb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80) {{ println!("FAIL Rust LDRSB sign extend"); failures += 1; }}

    mem.write64(0x100c, 0x8000_0001, 32);
    r = step64(0x{encoded["ldrsw"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_8000_0001) {{ println!("FAIL Rust LDRSW sign extend"); failures += 1; }}

    regs[2] = 0x1122_3344_5566_77a5;
    r = step64(0x{encoded["strb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x1005, 8) == 0xa5) {{ println!("FAIL Rust STRB truncates"); failures += 1; }}

    r = step64(0x{encoded["strh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x1006, 16) == 0x77a5) {{ println!("FAIL Rust STRH truncates"); failures += 1; }}

    r = step64(0x{encoded["str_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x1010, 32) == 0x5566_77a5) {{ println!("FAIL Rust STR W truncates"); failures += 1; }}

    regs[2] = 0x6000;
    mem.write64(0x6001, 0x80, 8);
    r = step64(0x{encoded["accel_ldru8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x80) {{ println!("FAIL Rust accelerator LDRU8"); failures += 1; }}
    mem.write64(0x6002, 0x8001, 16);
    r = step64(0x{encoded["accel_ldru16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8001) {{ println!("FAIL Rust accelerator LDRU16"); failures += 1; }}
    mem.write64(0x6004, 0x8000_0001, 32);
    r = step64(0x{encoded["accel_ldru32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0001) {{ println!("FAIL Rust accelerator LDRU32"); failures += 1; }}
    mem.write64(0x6001, 0x80, 8);
    r = step64(0x{encoded["accel_ldrs8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80) {{ println!("FAIL Rust accelerator LDRS8"); failures += 1; }}
    mem.write64(0x6004, 0x8000_0001, 32);
    r = step64(0x{encoded["accel_ldrs32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_8000_0001) {{ println!("FAIL Rust accelerator LDRS32"); failures += 1; }}
    regs[1] = 0x1122_3344_5566_77a5;
    r = step64(0x{encoded["accel_str8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x6001, 8) == 0xa5) {{ println!("FAIL Rust accelerator STR8"); failures += 1; }}
    r = step64(0x{encoded["accel_str16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x6002, 16) == 0x77a5) {{ println!("FAIL Rust accelerator STR16"); failures += 1; }}
    r = step64(0x{encoded["accel_str32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x6004, 32) == 0x5566_77a5) {{ println!("FAIL Rust accelerator STR32"); failures += 1; }}
    state64_write(&mut state, "sp", 0x6000, 64);
    mem.write64(0x6000, 0x8123_4567_89ab_cdef, 64);
    r = step64(0x{encoded["accel_ldr_reg"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8123_4567_89ab_cdef) {{ println!("FAIL Rust accelerator LDR register SP/XZR"); failures += 1; }}
    regs[5] = 2;
    r = step64(0x{encoded["accel_str_reg"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x6010, 64) == 0) {{ println!("FAIL Rust accelerator STR register SP/XZR"); failures += 1; }}
    regs[2] = u64::MAX; regs[3] = 2; regs[4] = 3;
    r = step64(0x{encoded["accel_madd64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 1) {{ println!("FAIL Rust accelerator MADD64"); failures += 1; }}
    r = step64(0x{encoded["accel_msub64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 5) {{ println!("FAIL Rust accelerator MSUB64"); failures += 1; }}
    regs[2] = 0xffff_ffff; regs[3] = 2; regs[4] = 3;
    r = step64(0x{encoded["accel_madd32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 1) {{ println!("FAIL Rust accelerator MADD32"); failures += 1; }}
    r = step64(0x{encoded["accel_msub32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 5) {{ println!("FAIL Rust accelerator MSUB32"); failures += 1; }}
    regs[2] = 100; regs[3] = 0;
    r = step64(0x{encoded["accel_udiv64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0) {{ println!("FAIL Rust accelerator UDIV64 zero"); failures += 1; }}
    regs[2] = 0xffff_ffff_ffff_fff9; regs[3] = 3;
    r = step64(0x{encoded["accel_sdiv64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_fffe) {{ println!("FAIL Rust accelerator SDIV64 truncation"); failures += 1; }}
    regs[2] = 0x8000_0000_0000_0000; regs[3] = u64::MAX;
    r = step64(0x{encoded["accel_sdiv64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000_0000_0000) {{ println!("FAIL Rust accelerator SDIV64 overflow"); failures += 1; }}
    regs[2] = 0xffff_ffff; regs[3] = 3;
    r = step64(0x{encoded["accel_udiv32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x5555_5555) {{ println!("FAIL Rust accelerator UDIV32"); failures += 1; }}
    regs[2] = 0x8000_0000; regs[3] = 0xffff_ffff;
    r = step64(0x{encoded["accel_sdiv32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000) {{ println!("FAIL Rust accelerator SDIV32 overflow"); failures += 1; }}
    regs[2] = 0x0123_4567_89ab_cdef; regs[3] = 0xfedc_ba98_7654_3210;
    state64_write(&mut state, "nzcv", 4, 4);
    r = step64(0x{encoded["accel_csel64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef) {{ println!("FAIL Rust accelerator CSEL64 true"); failures += 1; }}
    state64_write(&mut state, "nzcv", 0, 4);
    r = step64(0x{encoded["accel_csinc64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xfedc_ba98_7654_3211) {{ println!("FAIL Rust accelerator CSINC64 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csinv64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef) {{ println!("FAIL Rust accelerator CSINV64 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csneg64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdf0) {{ println!("FAIL Rust accelerator CSNEG64 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csel32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210) {{ println!("FAIL Rust accelerator CSEL32 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csinc32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3211) {{ println!("FAIL Rust accelerator CSINC32 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csinv32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef) {{ println!("FAIL Rust accelerator CSINV32 false"); failures += 1; }}
    r = step64(0x{encoded["accel_csneg32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdf0) {{ println!("FAIL Rust accelerator CSNEG32 false"); failures += 1; }}
    regs[2] = 0x0123_4567_89ab_cdef;
    r = step64(0x{encoded["accel_rbit64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xf7b3_d591_e6a2_c480) {{ println!("FAIL Rust accelerator RBIT64"); failures += 1; }}
    r = step64(0x{encoded["accel_rev16_64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x2301_6745_ab89_efcd) {{ println!("FAIL Rust accelerator REV16_64"); failures += 1; }}
    r = step64(0x{encoded["accel_rev32_64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x6745_2301_efcd_ab89) {{ println!("FAIL Rust accelerator REV32_64"); failures += 1; }}
    r = step64(0x{encoded["accel_rev64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xefcd_ab89_6745_2301) {{ println!("FAIL Rust accelerator REV64"); failures += 1; }}
    r = step64(0x{encoded["accel_clz64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 7) {{ println!("FAIL Rust accelerator CLZ64"); failures += 1; }}
    r = step64(0x{encoded["accel_cls64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 6) {{ println!("FAIL Rust accelerator CLS64"); failures += 1; }}
    r = step64(0x{encoded["accel_rbit32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xf7b3_d591) {{ println!("FAIL Rust accelerator RBIT32"); failures += 1; }}
    r = step64(0x{encoded["accel_rev16_32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xab89_efcd) {{ println!("FAIL Rust accelerator REV16_32"); failures += 1; }}
    r = step64(0x{encoded["accel_rev32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xefcd_ab89) {{ println!("FAIL Rust accelerator REV32"); failures += 1; }}
    r = step64(0x{encoded["accel_clz32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0) {{ println!("FAIL Rust accelerator CLZ32"); failures += 1; }}
    r = step64(0x{encoded["accel_cls32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0) {{ println!("FAIL Rust accelerator CLS32"); failures += 1; }}

    regs[2] = u64::MAX; regs[3] = 0; state64_write(&mut state, "nzcv", 2, 4);
    r = step64(0x{encoded["adcs_x_carry"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0 && state64_read(&state, "nzcv") == 6) {{ println!("FAIL Rust ADCS X carry-out"); failures += 1; }}
    regs[2] = 0; regs[3] = 0; state64_write(&mut state, "nzcv", 0, 4);
    r = step64(0x{encoded["sbcs_w_carry"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust SBCS W borrow"); failures += 1; }}
    regs[2] = u64::MAX; regs[3] = 0; state64_write(&mut state, "nzcv", 2, 4);
    r = step64(0x{encoded["accel_adcs64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0 && state64_read(&state, "nzcv") == 6) {{ println!("FAIL Rust accelerator ADCS64 carry-out"); failures += 1; }}
    regs[2] = 0; regs[3] = 0; state64_write(&mut state, "nzcv", 0, 4);
    r = step64(0x{encoded["accel_sbcs32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust accelerator SBCS32 borrow"); failures += 1; }}
    regs[2] = u64::MAX; regs[3] = u64::MAX;
    r = step64(0x{encoded["umulh_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_fffe) {{ println!("FAIL Rust UMULH X"); failures += 1; }}
    r = step64(0x{encoded["accel_umulh64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_fffe) {{ println!("FAIL Rust accelerator UMULH64"); failures += 1; }}
    regs[2] = 0x8000_0000_0000_0000; regs[3] = 2;
    r = step64(0x{encoded["smulh_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == u64::MAX) {{ println!("FAIL Rust SMULH X"); failures += 1; }}
    r = step64(0x{encoded["accel_smulh64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == u64::MAX) {{ println!("FAIL Rust accelerator SMULH64"); failures += 1; }}
    regs[2] = 0x0123_4567_89ab_cdef; regs[3] = 0xfedc_ba98_7654_3210;
    r = step64(0x{encoded["extr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xcdef_fedc_ba98_7654) {{ println!("FAIL Rust EXTR X asymmetric"); failures += 1; }}
    r = step64(0x{encoded["accel_extr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xcdef_fedc_ba98_7654) {{ println!("FAIL Rust accelerator EXTR64"); failures += 1; }}
    r = step64(0x{encoded["extr_w_zero"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210) {{ println!("FAIL Rust EXTR W zero"); failures += 1; }}
    r = step64(0x{encoded["accel_extr32_zero"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210) {{ println!("FAIL Rust accelerator EXTR32 zero"); failures += 1; }}
    regs[2] = 0xffff_0000_ffff_0000; regs[3] = 0x00ff_00ff_00ff_00ff;
    r = step64(0x{encoded["bic_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_0000_00ff_0000) {{ println!("FAIL Rust BIC X inverted LSR"); failures += 1; }}
    r = step64(0x{encoded["accel_bic64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_0000_00ff_0000) {{ println!("FAIL Rust accelerator BIC64"); failures += 1; }}
    regs[2] = 0x8000_00ff; regs[3] = 0x7fff_ffff; state64_write(&mut state, "nzcv", 15, 4);
    r = step64(0x{encoded["bics_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000 && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust BICS W negative"); failures += 1; }}
    state64_write(&mut state, "nzcv", 15, 4);
    r = step64(0x{encoded["accel_bics32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000 && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust accelerator BICS32"); failures += 1; }}
    regs[2] = 0; regs[3] = 1; state64_write(&mut state, "nzcv", 4, 4);
    r = step64(0x{encoded["ccmp_x_reg"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust CCMP X true flags"); failures += 1; }}
    state64_write(&mut state, "nzcv", 4, 4);
    r = step64(0x{encoded["accel_ccmp64_reg"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust accelerator CCMP64 true flags"); failures += 1; }}
    state64_write(&mut state, "nzcv", 0, 4);
    r = step64(0x{encoded["ccmn_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 9) {{ println!("FAIL Rust CCMN W false literal"); failures += 1; }}
    state64_write(&mut state, "nzcv", 0, 4);
    r = step64(0x{encoded["accel_ccmn32_imm"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 9) {{ println!("FAIL Rust accelerator CCMN32 false literal"); failures += 1; }}
    regs[4] = 0x9400; mem.write64(0x93ff, 0x80, 8);
    r = step64(0x{encoded["ldursb_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80) {{ println!("FAIL Rust LDURSB X negative offset"); failures += 1; }}
    r = step64(0x{encoded["accel_ldurs8_64_i9"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80) {{ println!("FAIL Rust accelerator LDURS8 X"); failures += 1; }}
    regs[2] = 0x1122_3344_5566_77a5;
    r = step64(0x{encoded["sturh_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x9403, 16) == 0x77a5) {{ println!("FAIL Rust STURH W positive offset"); failures += 1; }}
    r = step64(0x{encoded["accel_stur16_32_i9"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x9403, 16) == 0x77a5) {{ println!("FAIL Rust accelerator STUR16"); failures += 1; }}
    regs[4] = 0x9600; regs[5] = 0xffff_ffff; mem.write64(0x95fc, 0x8000_00a5, 32);
    r = step64(0x{encoded["ldrsw_x_reg"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_8000_00a5) {{ println!("FAIL Rust LDRSW SXTW scaled"); failures += 1; }}
    r = step64(0x{encoded["accel_ldrs32_64_reg"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_8000_00a5) {{ println!("FAIL Rust accelerator LDRSW register"); failures += 1; }}
    regs[5] = 3; regs[2] = 0x1122_3344_5566_77a5;
    r = step64(0x{encoded["strh_w_reg"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x9606, 16) == 0x77a5) {{ println!("FAIL Rust STRH UXTW scaled"); failures += 1; }}
    r = step64(0x{encoded["accel_str16_32_reg"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x9606, 16) == 0x77a5) {{ println!("FAIL Rust accelerator STRH register"); failures += 1; }}
    regs[2] = 0xaaaa_aaaa_ffff_ffff; regs[3] = 0x5555_5555_0000_0002; regs[4] = 7;
    r = step64(0x{encoded["smaddl"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 5) {{ println!("FAIL Rust SMADDL mixed width"); failures += 1; }}
    r = step64(0x{encoded["accel_smaddl"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 5) {{ println!("FAIL Rust accelerator SMADDL"); failures += 1; }}
    r = step64(0x{encoded["umaddl"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x2_0000_0005) {{ println!("FAIL Rust UMADDL mixed width"); failures += 1; }}
    r = step64(0x{encoded["accel_umaddl"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x2_0000_0005) {{ println!("FAIL Rust accelerator UMADDL"); failures += 1; }}

    regs[4] = 0x4000; regs[5] = 2;
    mem.write64(0x4010, 0x0102_0304_0506_0708, 64);
    r = step64(0x{encoded["ldr_reg"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0102_0304_0506_0708) {{ println!("FAIL Rust LDR register offset"); failures += 1; }}

    regs[2] = 0x8877_6655_4433_2211;
    r = step64(0x{encoded["str_reg"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x4010, 64) == regs[2]) {{ println!("FAIL Rust STR register offset"); failures += 1; }}

    regs[4] = 0x2000; mem.write64(0x2000, 0xaabb_ccdd_eeff_0011, 64);
    r = step64(0x{encoded["ldr_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xaabb_ccdd_eeff_0011 && regs[4] == 0x1ff8) {{ println!("FAIL Rust LDR post-index"); failures += 1; }}

    regs[4] = 0x2000; mem.write64(0x1ff8, 0x0123_4567_89ab_cdef, 64);
    r = step64(0x{encoded["ldr_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[4] == 0x1ff8) {{ println!("FAIL Rust LDR pre-index"); failures += 1; }}
    regs[4] = 0x2000;
    r = step64(0x{encoded["accel_ldr_pre"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[4] == 0x1ff8) {{ println!("FAIL Rust accelerator LDR pre-index"); failures += 1; }}

    regs[4] = 0x3000; regs[2] = 0xfeed_face_cafe_beef;
    r = step64(0x{encoded["str_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0x2ff0 && mem.read64(0x2ff0, 64) == regs[2]) {{ println!("FAIL Rust STR pre-index"); failures += 1; }}

    regs[4] = 0x3000;
    r = step64(0x{encoded["str_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0x2ff0 && mem.read64(0x3000, 64) == regs[2]) {{ println!("FAIL Rust STR post-index"); failures += 1; }}
    regs[4] = 0x3000;
    r = step64(0x{encoded["accel_str_post"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0x2ff0 && mem.read64(0x3000, 64) == regs[2]) {{ println!("FAIL Rust accelerator STR post-index"); failures += 1; }}

    regs[4] = 0xc000; mem.write64(0xbff8, 0x80, 8);
    r = step64(0x{encoded["ldrsb_w_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ff80 && regs[4] == 0xbff8) {{ println!("FAIL Rust LDRSB W pre-index"); failures += 1; }}
    regs[4] = 0xc000;
    r = step64(0x{encoded["accel_ldrs8_32_pre"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ff80 && regs[4] == 0xbff8) {{ println!("FAIL Rust accelerator LDRSB W pre-index"); failures += 1; }}

    regs[2] = 0x1122_3344_5566_77a5; regs[4] = 0xc200;
    r = step64(0x{encoded["strh_w_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0xc1f0 && mem.read64(0xc200, 16) == 0x77a5) {{ println!("FAIL Rust STRH W post-index"); failures += 1; }}
    regs[4] = 0xc200;
    r = step64(0x{encoded["accel_str16_32_post"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0xc1f0 && mem.read64(0xc200, 16) == 0x77a5) {{ println!("FAIL Rust accelerator STRH W post-index"); failures += 1; }}

    regs[4] = 0x5000;
    mem.write64(0x5010, 0x1111_2222_3333_4444, 64);
    mem.write64(0x5018, 0x5555_6666_7777_8888, 64);
    r = step64(0x{encoded["ldp_offset"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1111_2222_3333_4444 && regs[2] == 0x5555_6666_7777_8888 && regs[4] == 0x5000) {{ println!("FAIL Rust LDP offset"); failures += 1; }}

    regs[1] = 0x9999_aaaa_bbbb_cccc; regs[2] = 0xdddd_eeee_ffff_0000; regs[4] = 0x6000;
    r = step64(0x{encoded["stp_offset"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0x5ff0, 64) == regs[1] && mem.read64(0x5ff8, 64) == regs[2] && regs[4] == 0x6000) {{ println!("FAIL Rust STP offset"); failures += 1; }}

    regs[4] = 0x7000;
    mem.write64(0x7000, 0x0123_4567_89ab_cdef, 64);
    mem.write64(0x7008, 0xfedc_ba98_7654_3210, 64);
    r = step64(0x{encoded["ldp_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[2] == 0xfedc_ba98_7654_3210 && regs[4] == 0x7010) {{ println!("FAIL Rust LDP post-index"); failures += 1; }}

    regs[1] = 0xcafe_babe_dead_beef; regs[2] = 0x1020_3040_5060_7080; regs[4] = 0x8000;
    r = step64(0x{encoded["stp_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[4] == 0x7ff0 && mem.read64(0x7ff0, 64) == regs[1] && mem.read64(0x7ff8, 64) == regs[2]) {{ println!("FAIL Rust STP pre-index"); failures += 1; }}

    mem.write64(0x8ff8, 0x89ab_cdef, 32); mem.write64(0x8ffc, 0xfedc_ba98, 32);
    regs[1] = u64::MAX; regs[2] = u64::MAX; regs[4] = 0x9000;
    r = step64(0x{encoded["ldp_w_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef && regs[2] == 0xfedc_ba98 && regs[4] == 0x8ff8) {{ println!("FAIL Rust LDP W pre-index"); failures += 1; }}
    regs[1] = u64::MAX; regs[2] = u64::MAX; regs[4] = 0x9000;
    r = step64(0x{encoded["accel_ldp32_pre"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef && regs[2] == 0xfedc_ba98 && regs[4] == 0x8ff8) {{ println!("FAIL Rust accelerator LDP W pre-index"); failures += 1; }}

    regs[1] = 0xaaaa_aaaa_cafe_babe; regs[2] = 0xbbbb_bbbb_dead_beef; regs[4] = 0xa000;
    r = step64(0x{encoded["stp_w_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xa000, 32) == 0xcafe_babe && mem.read64(0xa004, 32) == 0xdead_beef && regs[4] == 0x9ff8) {{ println!("FAIL Rust STP W post-index"); failures += 1; }}
    regs[4] = 0xa000;
    r = step64(0x{encoded["accel_stp32_post"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xa000, 32) == 0xcafe_babe && mem.read64(0xa004, 32) == 0xdead_beef && regs[4] == 0x9ff8) {{ println!("FAIL Rust accelerator STP W post-index"); failures += 1; }}

    mem.write64(0xaff0, 0x0123_4567_89ab_cdef, 64); mem.write64(0xaff8, 0xfedc_ba98_7654_3210, 64);
    regs[4] = 0xb000;
    r = step64(0x{encoded["ldp_x_pre"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[2] == 0xfedc_ba98_7654_3210 && regs[4] == 0xaff0) {{ println!("FAIL Rust LDP X pre-index"); failures += 1; }}
    regs[4] = 0xb000;
    r = step64(0x{encoded["accel_ldp64_pre"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[2] == 0xfedc_ba98_7654_3210 && regs[4] == 0xaff0) {{ println!("FAIL Rust accelerator LDP X pre-index"); failures += 1; }}

    regs[1] = 0x1111_2222_3333_4444; regs[2] = 0x5555_6666_7777_8888; regs[4] = 0xc000;
    r = step64(0x{encoded["stp_x_post"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xc000, 64) == regs[1] && mem.read64(0xc008, 64) == regs[2] && regs[4] == 0xbff0) {{ println!("FAIL Rust STP X post-index"); failures += 1; }}
    regs[4] = 0xc000;
    r = step64(0x{encoded["accel_stp64_post"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xc000, 64) == regs[1] && mem.read64(0xc008, 64) == regs[2] && regs[4] == 0xbff0) {{ println!("FAIL Rust accelerator STP X post-index"); failures += 1; }}

    mem.write64(0xe000, 0x89ab_cdef, 32); regs[2] = 0xaaaa_aaaa_cafe_babe; regs[4] = 0xe000; state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["ldxr_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef && state[2].value == 0xe000 && state[3].value == 1) {{ println!("FAIL Rust LDXR W reservation"); failures += 1; }}
    r = step64(0x{encoded["stxr_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe000, 32) == 0xcafe_babe && state[3].value == 0) {{ println!("FAIL Rust STXR W success"); failures += 1; }}

    mem.write64(0xe000, 0x7654_3210, 32); state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["accel_ldxr32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210 && state[2].value == 0xe000 && state[3].value == 1) {{ println!("FAIL Rust accelerator LDXR W reservation"); failures += 1; }}
    r = step64(0x{encoded["accel_stxr32"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe000, 32) == 0xcafe_babe && state[3].value == 0) {{ println!("FAIL Rust accelerator STXR W success"); failures += 1; }}

    mem.write64(0xe100, 0x0123_4567_89ab_cdef, 64); regs[2] = 0xcafe_babe_dead_beef; regs[4] = 0xe100; state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["ldxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && state[2].value == 0xe100 && state[3].value == 1) {{ println!("FAIL Rust LDXR X reservation"); failures += 1; }}
    r = step64(0x{encoded["stxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe100, 64) == regs[2] && state[3].value == 0) {{ println!("FAIL Rust STXR X success"); failures += 1; }}

    mem.write64(0xe100, 0xfedc_ba98_7654_3210, 64); state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["accel_ldxr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xfedc_ba98_7654_3210 && state[2].value == 0xe100 && state[3].value == 1) {{ println!("FAIL Rust accelerator LDXR X reservation"); failures += 1; }}
    r = step64(0x{encoded["accel_stxr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe100, 64) == regs[2] && state[3].value == 0) {{ println!("FAIL Rust accelerator STXR X success"); failures += 1; }}

    mem.write64(0xe100, 0x1111_2222_3333_4444, 64); state[2].value = 0xe100; state[3].value = 0;
    r = step64(0x{encoded["stxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 1 && mem.read64(0xe100, 64) == 0x1111_2222_3333_4444) {{ println!("FAIL Rust STXR invalid reservation"); failures += 1; }}

    mem.write64(0xe200, 0x0123_4567_89ab_cdef, 64); regs[2] = 0x8877_6655_4433_2211; regs[4] = 0xe200; state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["ldaxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    r = step64(0x{encoded["stlxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[3] == 0 && mem.read64(0xe200, 64) == regs[2] && state[3].value == 0) {{ println!("FAIL Rust LDAXR/STLXR X"); failures += 1; }}

    mem.write64(0xe200, 0xfedc_ba98_7654_3210, 64); state[2].value = 0; state[3].value = 0;
    r = step64(0x{encoded["accel_ldaxr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    r = step64(0x{encoded["accel_stlxr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xfedc_ba98_7654_3210 && regs[3] == 0 && mem.read64(0xe200, 64) == regs[2] && state[3].value == 0) {{ println!("FAIL Rust accelerator LDAXR/STLXR X"); failures += 1; }}

    mem.write64(0xe280, 0x0123_4567_89ab_cdef, 64); mem.write64(0xe288, 0xfedc_ba98_7654_3210, 64);
    regs[4] = 0xe280; regs[6] = 19; regs[7] = 23; state[2].value = 0; state[3].value = 0; state[4].value = 0;
    r = step64(0x{encoded["ldxp_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && regs[2] == 0xfedc_ba98_7654_3210 && state[2].value == 0xe280 && state[3].value == 1 && state[4].value == 16) {{ println!("FAIL Rust LDXP X reservation"); failures += 1; }}
    r = step64(0x{encoded["stxp_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe280, 64) == 19 && mem.read64(0xe288, 64) == 23 && state[3].value == 0) {{ println!("FAIL Rust STXP X pair success"); failures += 1; }}

    mem.write64(0xe280, 29, 64); mem.write64(0xe288, 31, 64);
    state[2].value = 0xe280; state[3].value = 1; state[4].value = 8;
    r = step64(0x{encoded["stxp_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 1 && mem.read64(0xe280, 64) == 29 && mem.read64(0xe288, 64) == 31 && state[3].value == 0) {{ println!("FAIL Rust STXP X size mismatch is atomic"); failures += 1; }}

    mem.write64(0xe280, 37, 64); mem.write64(0xe288, 41, 64);
    state[2].value = 0; state[3].value = 0; state[4].value = 0;
    r = step64(0x{encoded["accel_ldaxp64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 37 && regs[2] == 41 && state[4].value == 16 && state[3].value == 1) {{ println!("FAIL Rust accelerator LDAXP64 reservation"); failures += 1; }}
    r = step64(0x{encoded["accel_stlxp64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 0 && mem.read64(0xe280, 64) == 19 && mem.read64(0xe288, 64) == 23 && state[3].value == 0) {{ println!("FAIL Rust accelerator STLXP64 pair success"); failures += 1; }}

    mem.write64(0xe2c0, 43, 64); regs[2] = 47; regs[4] = 0xe2c0;
    state[2].value = 0xe2c0; state[3].value = 1; state[4].value = 8;
    r = step64(0x{encoded["clrex"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state[2].value == 0xe2c0 && state[3].value == 0 && state[4].value == 8) {{ println!("FAIL Rust CLREX clears reservation"); failures += 1; }}
    r = step64(0x{encoded["stxr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 1 && mem.read64(0xe2c0, 64) == 43) {{ println!("FAIL Rust CLREX forces STXR failure"); failures += 1; }}

    state[2].value = 0xe2c0; state[3].value = 1; state[4].value = 8;
    r = step64(0x{encoded["accel_clrex"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state[2].value == 0xe2c0 && state[3].value == 0 && state[4].value == 8) {{ println!("FAIL Rust accelerator CLREX clears reservation"); failures += 1; }}
    r = step64(0x{encoded["accel_stxr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[3] == 1 && mem.read64(0xe2c0, 64) == 43) {{ println!("FAIL Rust accelerator CLREX forces STXR failure"); failures += 1; }}

    state[2].value = 0xe2c0; state[3].value = 1; state[4].value = 8; regs[1] = 53;
    r = step64(0x{encoded["dmb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[2].value == 0xe2c0 && state[3].value == 1 && state[4].value == 8) {{ println!("FAIL Rust DMB barrier"); failures += 1; }}
    r = step64(0x{encoded["dsb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust DSB barrier"); failures += 1; }}
    r = step64(0x{encoded["isb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust ISB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_dmb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator DMB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_dsb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator DSB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_isb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator ISB barrier"); failures += 1; }}
    r = step64(0x{encoded["sb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust SB barrier"); failures += 1; }}
    r = step64(0x{encoded["csdb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust CSDB barrier"); failures += 1; }}
    r = step64(0x{encoded["ssbb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust SSBB barrier"); failures += 1; }}
    r = step64(0x{encoded["pssbb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust PSSBB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_sb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator SB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_csdb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator CSDB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_ssbb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator SSBB barrier"); failures += 1; }}
    r = step64(0x{encoded["accel_pssbb"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 53 && state[3].value == 1) {{ println!("FAIL Rust accelerator PSSBB barrier"); failures += 1; }}

    state64_write(&mut state, "nzcv", 10, 4); regs[1] = 0;
    r = step64(0x{encoded["mrs_nzcv"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa000_0000 && state64_read(&state, "nzcv") == 10) {{ println!("FAIL Rust MRS NZCV"); failures += 1; }}
    regs[2] = 0x5123_4567_89ab_cdef;
    r = step64(0x{encoded["msr_nzcv"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust MSR NZCV"); failures += 1; }}
    state64_write(&mut state, "nzcv", 3, 4); regs[1] = 0;
    r = step64(0x{encoded["accel_mrs_nzcv"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x3000_0000) {{ println!("FAIL Rust accelerator MRS NZCV"); failures += 1; }}
    regs[2] = 0xf000_0000;
    r = step64(0x{encoded["accel_msr_nzcv"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "nzcv") == 15) {{ println!("FAIL Rust accelerator MSR NZCV"); failures += 1; }}
    state64_write(&mut state, "fpcr", 0x89ab_cdef, 32);
    r = step64(0x{encoded["mrs_fpcr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x89ab_cdef) {{ println!("FAIL Rust MRS FPCR"); failures += 1; }}
    regs[2] = 0xfedc_ba98_7654_3210;
    r = step64(0x{encoded["msr_fpcr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "fpcr") == 0x7654_3210) {{ println!("FAIL Rust MSR FPCR"); failures += 1; }}
    state64_write(&mut state, "fpsr", 0x1234_5678, 32);
    r = step64(0x{encoded["mrs_fpsr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1234_5678) {{ println!("FAIL Rust MRS FPSR"); failures += 1; }}
    r = step64(0x{encoded["msr_fpsr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "fpsr") == 0x7654_3210) {{ println!("FAIL Rust MSR FPSR"); failures += 1; }}
    state64_write(&mut state, "tpidr_el0", 0x0123_4567_89ab_cdef, 64);
    r = step64(0x{encoded["mrs_tpidr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef) {{ println!("FAIL Rust MRS TPIDR_EL0"); failures += 1; }}
    r = step64(0x{encoded["msr_tpidr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "tpidr_el0") == 0xfedc_ba98_7654_3210) {{ println!("FAIL Rust MSR TPIDR_EL0"); failures += 1; }}
    state64_write(&mut state, "tpidrro_el0", 0xa5a5_a5a5_5a5a_5a5a, 64);
    r = step64(0x{encoded["mrs_tpidrro"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa5a5_a5a5_5a5a_5a5a) {{ println!("FAIL Rust MRS TPIDRRO_EL0"); failures += 1; }}
    r = step64(0x{encoded["accel_mrs_fpcr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210) {{ println!("FAIL Rust accelerator MRS FPCR"); failures += 1; }}
    r = step64(0x{encoded["accel_msr_fpcr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "fpcr") == 0x7654_3210) {{ println!("FAIL Rust accelerator MSR FPCR"); failures += 1; }}
    r = step64(0x{encoded["accel_mrs_fpsr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7654_3210) {{ println!("FAIL Rust accelerator MRS FPSR"); failures += 1; }}
    r = step64(0x{encoded["accel_msr_fpsr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "fpsr") == 0x7654_3210) {{ println!("FAIL Rust accelerator MSR FPSR"); failures += 1; }}
    r = step64(0x{encoded["accel_mrs_tpidr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xfedc_ba98_7654_3210) {{ println!("FAIL Rust accelerator MRS TPIDR_EL0"); failures += 1; }}
    r = step64(0x{encoded["accel_msr_tpidr"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && state64_read(&state, "tpidr_el0") == 0xfedc_ba98_7654_3210) {{ println!("FAIL Rust accelerator MSR TPIDR_EL0"); failures += 1; }}
    r = step64(0x{encoded["accel_mrs_tpidrro"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa5a5_a5a5_5a5a_5a5a) {{ println!("FAIL Rust accelerator MRS TPIDRRO_EL0"); failures += 1; }}

    mem.write64(0xe2d0, 0xa5, 8); regs[2] = 0x1234; regs[4] = 0xe2d0; state[3].value = 1;
    r = step64(0x{encoded["ldarb_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa5 && state[3].value == 1) {{ println!("FAIL Rust LDARB"); failures += 1; }}
    r = step64(0x{encoded["stlrb_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xe2d0, 8) == 0x34 && state[3].value == 1) {{ println!("FAIL Rust STLRB"); failures += 1; }}
    mem.write64(0xe2d0, 0x5a, 8);
    r = step64(0x{encoded["accel_ldar8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x5a && state[3].value == 1) {{ println!("FAIL Rust accelerator LDAR8"); failures += 1; }}
    r = step64(0x{encoded["accel_stlr8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xe2d0, 8) == 0x34 && state[3].value == 1) {{ println!("FAIL Rust accelerator STLR8"); failures += 1; }}

    mem.write64(0xe2e0, 0x0123_4567_89ab_cdef, 64); regs[2] = 0xfedc_ba98_7654_3210; regs[4] = 0xe2e0;
    r = step64(0x{encoded["ldar_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0123_4567_89ab_cdef && state[3].value == 1) {{ println!("FAIL Rust LDAR X"); failures += 1; }}
    r = step64(0x{encoded["stlr_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xe2e0, 64) == 0xfedc_ba98_7654_3210 && state[3].value == 1) {{ println!("FAIL Rust STLR X"); failures += 1; }}
    mem.write64(0xe2e0, 0x1111_2222_3333_4444, 64);
    r = step64(0x{encoded["accel_ldar64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1111_2222_3333_4444 && state[3].value == 1) {{ println!("FAIL Rust accelerator LDAR64"); failures += 1; }}
    r = step64(0x{encoded["accel_stlr64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && mem.read64(0xe2e0, 64) == 0xfedc_ba98_7654_3210 && state[3].value == 1) {{ println!("FAIL Rust accelerator STLR64"); failures += 1; }}

    mem.write64(0xe300, 0x0123_4567_89ab_cdef, 64); regs[1] = 0x8877_6655_4433_2211; regs[2] = 0; regs[4] = 0xe300;
    r = step64(0x{encoded["swp_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x0123_4567_89ab_cdef && mem.read64(0xe300, 64) == 0x8877_6655_4433_2211) {{ println!("FAIL Rust SWP X"); failures += 1; }}

    mem.write64(0xe300, 0xfedc_ba98_7654_3210, 64); regs[1] = 0x1122_3344_5566_7788; regs[2] = 0;
    r = step64(0x{encoded["accel_swp64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xfedc_ba98_7654_3210 && mem.read64(0xe300, 64) == 0x1122_3344_5566_7788) {{ println!("FAIL Rust accelerator SWP X"); failures += 1; }}

    mem.write64(0xe300, 0x0102_0304_0506_0708, 64); regs[1] = 0xa1a2_a3a4_a5a6_a7a8;
    r = step64(0x{encoded["swp_x_overlap"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0102_0304_0506_0708 && mem.read64(0xe300, 64) == 0xa1a2_a3a4_a5a6_a7a8) {{ println!("FAIL Rust SWP X overlapping source/destination"); failures += 1; }}

    mem.write64(0xe300, 0x1112_1314_1516_1718, 64); regs[1] = 0xb1b2_b3b4_b5b6_b7b8;
    r = step64(0x{encoded["accel_swp64_overlap"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1112_1314_1516_1718 && mem.read64(0xe300, 64) == 0xb1b2_b3b4_b5b6_b7b8) {{ println!("FAIL Rust accelerator SWP X overlapping source/destination"); failures += 1; }}

    mem.write64(0xe300, 0x2122_2324_2526_2728, 64); regs[1] = 0xc1c2_c3c4_c5c6_c7c8; regs[2] = 0;
    r = step64(0x{encoded["swpal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x2122_2324_2526_2728 && mem.read64(0xe300, 64) == 0xc1c2_c3c4_c5c6_c7c8) {{ println!("FAIL Rust SWPAL X"); failures += 1; }}

    mem.write64(0xe300, 0x3132_3334_3536_3738, 64); regs[1] = 0xd1d2_d3d4_d5d6_d7d8; regs[2] = 0;
    r = step64(0x{encoded["accel_swpal64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x3132_3334_3536_3738 && mem.read64(0xe300, 64) == 0xd1d2_d3d4_d5d6_d7d8) {{ println!("FAIL Rust accelerator SWPAL X"); failures += 1; }}

    mem.write64(0xe380, 0xa5, 8); regs[1] = 0x1234; regs[2] = u64::MAX; regs[4] = 0xe380;
    r = step64(0x{encoded["swpalb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xa5 && mem.read64(0xe380, 8) == 0x34) {{ println!("FAIL Rust SWPALB"); failures += 1; }}

    mem.write64(0xe380, 0x7e, 8); regs[1] = 0x1ff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_swpal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x7e && mem.read64(0xe380, 8) == 0xff) {{ println!("FAIL Rust accelerator SWPAL8"); failures += 1; }}

    mem.write64(0xe380, 0xbeef, 16); regs[1] = 0x1234_5678; regs[2] = u64::MAX;
    r = step64(0x{encoded["swpalh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xbeef && mem.read64(0xe380, 16) == 0x5678) {{ println!("FAIL Rust SWPALH"); failures += 1; }}

    mem.write64(0xe380, 0x8001, 16); regs[1] = 0xffff_0002; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_swpal16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8001 && mem.read64(0xe380, 16) == 0x0002) {{ println!("FAIL Rust accelerator SWPAL16"); failures += 1; }}

    mem.write64(0xe3c0, 250, 8); regs[1] = 10; regs[2] = u64::MAX; regs[4] = 0xe3c0;
    r = step64(0x{encoded["ldaddalb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 250 && mem.read64(0xe3c0, 8) == 4) {{ println!("FAIL Rust LDADDALB"); failures += 1; }}

    mem.write64(0xe3c0, 1, 8); regs[1] = 0x1ff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldaddal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 1 && mem.read64(0xe3c0, 8) == 0) {{ println!("FAIL Rust accelerator LDADDAL8"); failures += 1; }}

    mem.write64(0xe3c0, 0xfffe, 16); regs[1] = 5; regs[2] = u64::MAX;
    r = step64(0x{encoded["ldaddalh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xfffe && mem.read64(0xe3c0, 16) == 3) {{ println!("FAIL Rust LDADDALH"); failures += 1; }}

    mem.write64(0xe3c0, 0x8000, 16); regs[1] = 0x8001; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldaddal16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8000 && mem.read64(0xe3c0, 16) == 1) {{ println!("FAIL Rust accelerator LDADDAL16"); failures += 1; }}

    mem.write64(0xe3d0, 0xf3, 8); regs[1] = 0x35; regs[2] = u64::MAX; regs[4] = 0xe3d0;
    r = step64(0x{encoded["ldclralb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xf3 && mem.read64(0xe3d0, 8) == 0xc2) {{ println!("FAIL Rust LDCLRALB"); failures += 1; }}

    mem.write64(0xe3d0, 0xff, 8); regs[1] = 0x0f; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldclral8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xff && mem.read64(0xe3d0, 8) == 0xf0) {{ println!("FAIL Rust accelerator LDCLRAL8"); failures += 1; }}

    mem.write64(0xe3d0, 0xf0ff, 16); regs[1] = 0x00f3; regs[2] = u64::MAX;
    r = step64(0x{encoded["ldclralh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xf0ff && mem.read64(0xe3d0, 16) == 0xf00c) {{ println!("FAIL Rust LDCLRALH"); failures += 1; }}

    mem.write64(0xe3d0, 0xffff, 16); regs[1] = 0xf0f0; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldclral16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xffff && mem.read64(0xe3d0, 16) == 0x0f0f) {{ println!("FAIL Rust accelerator LDCLRAL16"); failures += 1; }}

    mem.write64(0xe3e0, 0xaa, 8); regs[1] = 0x0f; regs[2] = u64::MAX; regs[4] = 0xe3e0;
    r = step64(0x{encoded["ldeoralb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xaa && mem.read64(0xe3e0, 8) == 0xa5) {{ println!("FAIL Rust LDEORALB"); failures += 1; }}

    mem.write64(0xe3e0, 0xf0, 8); regs[1] = 0xff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldeoral8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xf0 && mem.read64(0xe3e0, 8) == 0x0f) {{ println!("FAIL Rust accelerator LDEORAL8"); failures += 1; }}

    mem.write64(0xe3e0, 0x55aa, 16); regs[1] = 0x0ff0; regs[2] = u64::MAX;
    r = step64(0x{encoded["ldeoralh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x55aa && mem.read64(0xe3e0, 16) == 0x5a5a) {{ println!("FAIL Rust LDEORALH"); failures += 1; }}

    mem.write64(0xe3e0, 0xaaaa, 16); regs[1] = 0xffff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldeoral16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xaaaa && mem.read64(0xe3e0, 16) == 0x5555) {{ println!("FAIL Rust accelerator LDEORAL16"); failures += 1; }}

    mem.write64(0xe3f0, 0x10, 8); regs[1] = 0x81; regs[2] = u64::MAX; regs[4] = 0xe3f0;
    r = step64(0x{encoded["ldsetalb"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x10 && mem.read64(0xe3f0, 8) == 0x91) {{ println!("FAIL Rust LDSETALB"); failures += 1; }}

    mem.write64(0xe3f0, 0, 8); regs[1] = 0xff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldsetal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0 && mem.read64(0xe3f0, 8) == 0xff) {{ println!("FAIL Rust accelerator LDSETAL8"); failures += 1; }}

    mem.write64(0xe3f0, 0x1001, 16); regs[1] = 0x0ff0; regs[2] = u64::MAX;
    r = step64(0x{encoded["ldsetalh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x1001 && mem.read64(0xe3f0, 16) == 0x1ff1) {{ println!("FAIL Rust LDSETALH"); failures += 1; }}

    mem.write64(0xe3f0, 0x8000, 16); regs[1] = 0x7fff; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldsetal16"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8000 && mem.read64(0xe3f0, 16) == 0xffff) {{ println!("FAIL Rust accelerator LDSETAL16"); failures += 1; }}

    mem.write64(0xe500, 0x8000_0000_0000_0000, 64); regs[1] = 1; regs[2] = u64::MAX; regs[4] = 0xe500;
    r = step64(0x{encoded["ldsmaxal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8000_0000_0000_0000 && mem.read64(0xe500, 64) == 1) {{ println!("FAIL Rust LDSMAXAL X signed"); failures += 1; }}

    mem.write64(0xe500, 0x80, 8); regs[1] = 1; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_ldsminal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x80 && mem.read64(0xe500, 8) == 0x80) {{ println!("FAIL Rust accelerator LDSMINAL8 signed"); failures += 1; }}

    mem.write64(0xe500, 0x8000, 16); regs[1] = 0x7fff; regs[2] = u64::MAX;
    r = step64(0x{encoded["ldumaxalh"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8000 && mem.read64(0xe500, 16) == 0x8000) {{ println!("FAIL Rust LDUMAXALH unsigned"); failures += 1; }}

    mem.write64(0xe500, 0x8000_0000_0000_0000, 64); regs[1] = 1; regs[2] = u64::MAX;
    r = step64(0x{encoded["accel_lduminal64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x8000_0000_0000_0000 && mem.read64(0xe500, 64) == 1) {{ println!("FAIL Rust accelerator LDUMINAL64 unsigned"); failures += 1; }}

    mem.write64(0xe500, 7, 64); regs[1] = 7; regs[2] = 19; regs[4] = 0xe500;
    r = step64(0x{encoded["casal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 7 && mem.read64(0xe500, 64) == 19) {{ println!("FAIL Rust CASAL X success"); failures += 1; }}
    mem.write64(0xe500, 11, 64); regs[1] = 7; regs[2] = 23;
    r = step64(0x{encoded["casal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 11 && mem.read64(0xe500, 64) == 11) {{ println!("FAIL Rust CASAL X failure"); failures += 1; }}

    mem.write64(0xe500, 0xa5, 8); regs[1] = 0xffff_00a5; regs[2] = 0x5a;
    r = step64(0x{encoded["accel_casal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa5 && mem.read64(0xe500, 8) == 0x5a) {{ println!("FAIL Rust accelerator CASAL8 success"); failures += 1; }}
    mem.write64(0xe500, 0xa5, 8); regs[1] = 0xa4; regs[2] = 0x33;
    r = step64(0x{encoded["accel_casal8"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xa5 && mem.read64(0xe500, 8) == 0xa5) {{ println!("FAIL Rust accelerator CASAL8 failure"); failures += 1; }}

    mem.write64(0xe600, 7, 64); mem.write64(0xe608, 11, 64);
    regs[2] = 7; regs[3] = 11; regs[6] = 19; regs[7] = 23; regs[4] = 0xe600;
    r = step64(0x{encoded["caspal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 7 && regs[3] == 11 && mem.read64(0xe600, 64) == 19 && mem.read64(0xe608, 64) == 23) {{ println!("FAIL Rust CASPAL X pair success"); failures += 1; }}
    mem.write64(0xe600, 29, 64); mem.write64(0xe608, 31, 64);
    regs[2] = 29; regs[3] = 37; regs[6] = 41; regs[7] = 43;
    r = step64(0x{encoded["caspal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 29 && regs[3] == 31 && mem.read64(0xe600, 64) == 29 && mem.read64(0xe608, 64) == 31) {{ println!("FAIL Rust CASPAL X pair failure"); failures += 1; }}

    mem.write64(0xe600, 47, 64); mem.write64(0xe608, 53, 64);
    regs[2] = 47; regs[3] = 53; regs[6] = 59; regs[7] = 61;
    r = step64(0x{encoded["accel_caspal64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 47 && regs[3] == 53 && mem.read64(0xe600, 64) == 59 && mem.read64(0xe608, 64) == 61) {{ println!("FAIL Rust accelerator CASPAL64 pair success"); failures += 1; }}

    mem.write64(0xe400, 7, 64); regs[1] = 5; regs[2] = 0; regs[4] = 0xe400;
    r = step64(0x{encoded["ldaddal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 7 && mem.read64(0xe400, 64) == 12) {{ println!("FAIL Rust LDADDAL X"); failures += 1; }}

    mem.write64(0xe400, 11, 64); regs[1] = 9; regs[2] = 0;
    r = step64(0x{encoded["accel_ldaddal64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 11 && mem.read64(0xe400, 64) == 20) {{ println!("FAIL Rust accelerator LDADDAL X"); failures += 1; }}

    mem.write64(0xe400, 13, 64); regs[1] = 6;
    r = step64(0x{encoded["ldadd_x_overlap"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 13 && mem.read64(0xe400, 64) == 19) {{ println!("FAIL Rust LDADD X overlapping source/destination"); failures += 1; }}

    mem.write64(0xe400, 17, 64); regs[1] = 8;
    r = step64(0x{encoded["accel_ldadd64_overlap"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 17 && mem.read64(0xe400, 64) == 25) {{ println!("FAIL Rust accelerator LDADD X overlapping source/destination"); failures += 1; }}

    mem.write64(0xe400, 0xff0f, 64); regs[1] = 0x0f0f; regs[2] = 0;
    r = step64(0x{encoded["ldclral_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xff0f && mem.read64(0xe400, 64) == 0xf000) {{ println!("FAIL Rust LDCLRAL X"); failures += 1; }}

    mem.write64(0xe400, 0xffff, 64); regs[1] = 0x00ff; regs[2] = 0;
    r = step64(0x{encoded["accel_ldclral64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xffff && mem.read64(0xe400, 64) == 0xff00) {{ println!("FAIL Rust accelerator LDCLRAL X"); failures += 1; }}

    mem.write64(0xe400, 0xf0f0, 64); regs[1] = 0x0ff0; regs[2] = 0;
    r = step64(0x{encoded["ldeoral_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xf0f0 && mem.read64(0xe400, 64) == 0xff00) {{ println!("FAIL Rust LDEORAL X"); failures += 1; }}

    mem.write64(0xe400, 0x0f0f, 64); regs[1] = 0x00ff; regs[2] = 0;
    r = step64(0x{encoded["accel_ldeoral64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x0f0f && mem.read64(0xe400, 64) == 0x0ff0) {{ println!("FAIL Rust accelerator LDEORAL X"); failures += 1; }}

    mem.write64(0xe400, 0xf000, 64); regs[1] = 0x0f0f; regs[2] = 0;
    r = step64(0x{encoded["ldsetal_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0xf000 && mem.read64(0xe400, 64) == 0xff0f) {{ println!("FAIL Rust LDSETAL X"); failures += 1; }}

    mem.write64(0xe400, 0x00f0, 64); regs[1] = 0x0f0f; regs[2] = 0;
    r = step64(0x{encoded["accel_ldsetal64"]:08x}, Some("accelerator_scalar64"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[2] == 0x00f0 && mem.read64(0xe400, 64) == 0x0fff) {{ println!("FAIL Rust accelerator LDSETAL X"); failures += 1; }}

    r = step64(0x{encoded["adr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0x1000, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x13345) {{ println!("FAIL Rust ADR"); failures += 1; }}

    r = step64(0x{encoded["adrp"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0x12345, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x14000) {{ println!("FAIL Rust ADRP"); failures += 1; }}

    r = step64(0x{encoded["b_back"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0x9000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0x8ffc) {{ println!("FAIL Rust B backward"); failures += 1; }}

    r = step64(0x{encoded["bl"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xa000, &mut state);
    checks += 1; if !(r.ok && regs[30] == 0xa004 && r.next_pc == 0xa008 && r.wrote == Some(30)) {{ println!("FAIL Rust BL link"); failures += 1; }}

    regs[5] = 0xbeef_0000;
    r = step64(0x{encoded["br"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xb000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xbeef_0000) {{ println!("FAIL Rust BR"); failures += 1; }}

    regs[30] = 0xcafe_0000;
    r = step64(0x{encoded["ret"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xc000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xcafe_0000) {{ println!("FAIL Rust RET"); failures += 1; }}

    regs[30] = 0xd00d_1000;
    r = step64(0x{encoded["blr"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xd100, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xd00d_1000 && regs[30] == 0xd104) {{ println!("FAIL Rust BLR X30 ordering"); failures += 1; }}

    regs[1] = 0;
    r = step64(0x{encoded["cbz_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe00c) {{ println!("FAIL Rust CBZ X"); failures += 1; }}

    regs[1] = 1;
    r = step64(0x{encoded["cbnz_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe000, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xdffc) {{ println!("FAIL Rust CBNZ X"); failures += 1; }}

    regs[1] = 0x1_0000_0000;
    r = step64(0x{encoded["cbz_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe100, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe108) {{ println!("FAIL Rust CBZ W"); failures += 1; }}

    regs[1] = 0x1_0000_0001;
    r = step64(0x{encoded["cbnz_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe100, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe108) {{ println!("FAIL Rust CBNZ W"); failures += 1; }}

    regs[1] = 0;
    r = step64(0x{encoded["tbz_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe200, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe208) {{ println!("FAIL Rust TBZ W"); failures += 1; }}

    regs[1] = 1 << 5;
    r = step64(0x{encoded["tbnz_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe200, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe1fc) {{ println!("FAIL Rust TBNZ W"); failures += 1; }}

    regs[1] = 0;
    r = step64(0x{encoded["tbz_x_high"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe300, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe308) {{ println!("FAIL Rust TBZ X high"); failures += 1; }}

    regs[1] = 1 << 40;
    r = step64(0x{encoded["tbnz_x_high"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0xe300, &mut state);
    checks += 1; if !(r.ok && r.next_pc == 0xe308) {{ println!("FAIL Rust TBNZ X high"); failures += 1; }}

    regs[2] = 0xff; regs[3] = 0x8000_0000_0000_0000;
    r = step64(0x{encoded["and_x_shifted"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x80) {{ println!("FAIL Rust AND X shifted"); failures += 1; }}

    regs[2] = 1; regs[3] = 0x8000_0000;
    r = step64(0x{encoded["orr_w_shifted"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_fff9) {{ println!("FAIL Rust ORR W shifted"); failures += 1; }}

    regs[2] = 0x8000_0000_0000_00ff; regs[3] = 0x8000_0000_0000_0000; state[1].value = 15;
    r = step64(0x{encoded["ands_x_shifted"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000_0000_0000 && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust ANDS X flags"); failures += 1; }}
    regs[2] = 0xf0; regs[3] = 0x0f; state[1].value = 15;
    r = step64(0x{encoded["tst_x_shifted"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.wrote.is_none() && state64_read(&state, "nzcv") == 4) {{ println!("FAIL Rust TST X alias"); failures += 1; }}
    regs[2] = 0xffff_ffff_8000_00ff; regs[3] = 0x8000_0000; state[1].value = 15;
    r = step64(0x{encoded["ands_w_shifted"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000 && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust ANDS W flags"); failures += 1; }}

    regs[2] = 0x8000_0000_0000_0001; regs[3] = 68;
    for (word, expected, label) in [
        (0x{encoded["lslv_x"]:08x}, 0x10, "LSLV X"),
        (0x{encoded["lsrv_x"]:08x}, 0x0800_0000_0000_0000, "LSRV X"),
        (0x{encoded["asrv_x"]:08x}, 0xf800_0000_0000_0000, "ASRV X"),
        (0x{encoded["rorv_x"]:08x}, 0x1800_0000_0000_0000, "RORV X"),
    ] {{
        r = step64(word, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
        checks += 1; if !(r.ok && regs[1] == expected) {{ println!("FAIL Rust {{}}", label); failures += 1; }}
    }}

    regs[2] = 0x8000_0001; regs[3] = 36;
    for (word, expected, label) in [
        (0x{encoded["lslv_w"]:08x}, 0x10, "LSLV W"),
        (0x{encoded["lsrv_w"]:08x}, 0x0800_0000, "LSRV W"),
        (0x{encoded["asrv_w"]:08x}, 0xf800_0000, "ASRV W"),
        (0x{encoded["rorv_w"]:08x}, 0x1800_0000, "RORV W"),
    ] {{
        r = step64(word, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
        checks += 1; if !(r.ok && regs[1] == expected) {{ println!("FAIL Rust {{}}", label); failures += 1; }}
    }}

    r = step64(0x{encoded["movz_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x0000_abcd_0000_0000) {{ println!("FAIL Rust MOVZ X"); failures += 1; }}
    r = step64(0x{encoded["movn_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_edcb_ffff) {{ println!("FAIL Rust MOVN X"); failures += 1; }}
    regs[1] = 0x1122_3344_5566_7788;
    r = step64(0x{encoded["movk_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1122_3344_abcd_7788) {{ println!("FAIL Rust MOVK X"); failures += 1; }}

    regs[2] = 0x1234;
    r = step64(0x{encoded["and_x_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x34) {{ println!("FAIL Rust AND X immediate"); failures += 1; }}
    regs[2] = 0;
    r = step64(0x{encoded["orr_x_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7f7f_7f7f_7f7f_7f7f) {{ println!("FAIL Rust ORR X immediate"); failures += 1; }}
    r = step64(0x{encoded["eor_x_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xff00_0000_0000_00ff) {{ println!("FAIL Rust EOR X immediate"); failures += 1; }}

    regs[2] = 0x1234;
    r = step64(0x{encoded["and_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x34) {{ println!("FAIL Rust AND W immediate"); failures += 1; }}
    regs[2] = 0;
    r = step64(0x{encoded["orr_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x7f7f_7f7f) {{ println!("FAIL Rust ORR W immediate"); failures += 1; }}
    r = step64(0x{encoded["eor_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xf0f0_f0f0) {{ println!("FAIL Rust EOR W immediate"); failures += 1; }}
    regs[2] = 0x100; state[1].value = 15;
    r = step64(0x{encoded["tst_x_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && r.wrote.is_none() && state64_read(&state, "nzcv") == 4) {{ println!("FAIL Rust TST X immediate"); failures += 1; }}
    regs[2] = 0x8000_0000; state[1].value = 15;
    r = step64(0x{encoded["ands_w_imm"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x8000_0000 && state64_read(&state, "nzcv") == 8) {{ println!("FAIL Rust ANDS W immediate"); failures += 1; }}
    for (word, label) in [
        (0x{encoded["reserved_x_n1"]:08x}, "reserved logical immediate X N=1"),
        (0x{encoded["reserved_x_n0"]:08x}, "reserved logical immediate X N=0"),
        (0x{encoded["reserved_w"]:08x}, "reserved logical immediate W"),
        (0x{encoded["reserved_sbfm_w_immr"]:08x}, "reserved SBFM W immr"),
        (0x{encoded["reserved_ubfm_w_imms"]:08x}, "reserved UBFM W imms"),
    ] {{
        r = step64(word, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
        checks += 1; if r.ok {{ println!("FAIL Rust {{}}", label); failures += 1; }}
    }}

    regs[2] = 0x1234_5678;
    r = step64(0x{encoded["ubfm_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x56) {{ println!("FAIL Rust UBFM X"); failures += 1; }}
    regs[2] = 0x8000;
    r = step64(0x{encoded["sbfm_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ffff_ffff_ff80) {{ println!("FAIL Rust SBFM X"); failures += 1; }}
    regs[1] = 0x1122_3344_5566_7788; regs[2] = 0xab;
    r = step64(0x{encoded["bfm_x"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x1122_3344_5566_ab88) {{ println!("FAIL Rust BFM X"); failures += 1; }}

    regs[2] = 0x1234_5678;
    r = step64(0x{encoded["ubfm_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x56) {{ println!("FAIL Rust UBFM W"); failures += 1; }}
    regs[2] = 0x8000;
    r = step64(0x{encoded["sbfm_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0xffff_ff80) {{ println!("FAIL Rust SBFM W"); failures += 1; }}
    regs[1] = 0x5566_7788; regs[2] = 0xab;
    r = step64(0x{encoded["bfm_w"]:08x}, Some("aarch64_base"), &mut regs, &mut mem, 0, &mut state);
    checks += 1; if !(r.ok && regs[1] == 0x5566_ab88) {{ println!("FAIL Rust BFM W"); failures += 1; }}

    println!("{{}} Rust wide-state checks, {{}} failures", checks, failures);
    std::process::exit(if failures == 0 {{ 0 }} else {{ 1 }});
}}
"""


def main() -> int:
    global AXIS_FILE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "axis_file",
        nargs="?",
        type=Path,
        default=AXIS_FILE,
        help="AXIS source to compile (defaults to the canonical Lisp AArch64 seed)",
    )
    args = parser.parse_args()
    AXIS_FILE = args.axis_file

    workdir = Path(tempfile.mkdtemp(prefix="axis_a64_native_"))
    emit("emit-lift-python", workdir / "axis_lift.py")
    sys.path.insert(0, str(workdir))
    lift = importlib.import_module("axis_lift")
    entries = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    encoded = words(entries)

    emit("emit-lift-c", workdir / "axis_lift.h")
    emit("emit-semantics-c", workdir / "axis_semantics.h")
    emit("emit-exec-c", workdir / "axis_exec.h")
    c_path = workdir / "driver.c"
    c_path.write_text(c_driver(encoded))
    c_bin = workdir / "driver_c"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-DAXIS_IMPL_STUBS",
         "-I", str(workdir), str(c_path), "-o", str(c_bin)],
        check=True,
    )
    c_result = subprocess.run([str(c_bin)], text=True, capture_output=True)
    print(c_result.stdout.strip())

    rust_result_code = 0
    if shutil.which("rustc"):
        sem = workdir / "axis_semantics.rs"
        lift_rs = workdir / "axis_lift.rs"
        exec_rs = workdir / "axis_exec.rs"
        emit("emit-semantics-rust", sem)
        emit("emit-lift-rust", lift_rs)
        emit("emit-exec-rust", exec_rs)
        rust_path = workdir / "driver.rs"
        rust_path.write_text(
            sem.read_text()
            + "\n"
            + lift_rs.read_text()
            + "\n"
            + exec_rs.read_text()
            + "\n"
            + rust_driver(encoded)
        )
        rust_bin = workdir / "driver_rust"
        subprocess.run(
            ["rustc", "--edition", "2021", "-A", "warnings", "--cfg", "axis_impl_stubs", str(rust_path), "-o", str(rust_bin)],
            check=True,
        )
        rust_result = subprocess.run([str(rust_bin)], text=True, capture_output=True)
        print(rust_result.stdout.strip())
        rust_result_code = rust_result.returncode
    else:
        print("Rust wide-state checks: SKIP (rustc not found)")

    ok = c_result.returncode == 0 and rust_result_code == 0
    print("AArch64 native wide execution: PASS" if ok else "AArch64 native wide execution: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
