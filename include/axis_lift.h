/* AXIS lifter: bytes in, LLVM IR out, from a compiled consumer.
 *
 * Link against `libaxis_adl.a` (or `.dylib`/`.so`) built by `cargo build
 * --release`. This is the same lifter `axis lift-llvm` drives; the difference
 * is that a description is parsed once into a handle instead of once per call.
 *
 * Every query takes an output buffer and a capacity and returns the number of
 * bytes the answer needs -- ask with a capacity of zero to size the buffer,
 * then ask again. The result is always NUL-terminated when it fits. A negative
 * return is a failure and `axis_lift_last_error()` says what happened.
 *
 * Nothing here allocates on the caller's behalf, and nothing but the handle
 * outlives a call.
 */
#ifndef AXIS_LIFT_H
#define AXIS_LIFT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AxisLifter axis_lifter;

/* Parse a description. Returns NULL on failure. */
axis_lifter *axis_lift_open(const char *axisl_path);
void         axis_lift_close(axis_lifter *handle);

/* The last failure, or "". Owned by the library; do not free. */
const char *axis_lift_last_error(void);

/* Where the basic blocks are, as a human-readable report. */
intptr_t axis_lift_blocks(const axis_lifter *handle,
                          const unsigned char *bytes, intptr_t byte_count,
                          uint64_t address, const char *isa,
                          char *out, intptr_t capacity);

/* The region as an LLVM module: one function per basic block,
 *
 *   define void @axis_block_<addr>(iW* %regs, i8* %mem, iW* %status, iW* %state)
 *
 * which runs the block and stores in %status[0] the address control goes to
 * next. Composing them is the caller's. */
intptr_t axis_lift_llvm(const axis_lifter *handle,
                        const unsigned char *bytes, intptr_t byte_count,
                        uint64_t address, const char *isa,
                        char *out, intptr_t capacity);

/* The bytes-independent part of a lifted module: the semantics helpers the
 * lowered arithmetic calls. Thirty thousand lines for AArch64, and the same for
 * every region -- so a consumer lifting a binary asks once, then appends each
 * region's blocks from axis_lift_llvm_blocks(). axis_lift_llvm() is the two
 * together, for a caller that wants one self-contained module. */
intptr_t axis_lift_preamble(const axis_lifter *handle,
                            char *out, intptr_t capacity);

/* A region's block functions, without the preamble. */
intptr_t axis_lift_llvm_blocks(const axis_lifter *handle,
                               const unsigned char *bytes, intptr_t byte_count,
                               uint64_t address, const char *isa,
                               char *out, intptr_t capacity);

/* One "mnemonic\tverdict" line per instruction: `ok`, or why it is refused.
 * Acceptance is a statement about the rules, not a promise about the result. */
intptr_t axis_lift_support(const axis_lifter *handle,
                           char *out, intptr_t capacity);

/* How many encodings the description has; -1 for a null handle. */
int axis_lift_instruction_count(const axis_lifter *handle);

#ifdef __cplusplus
}
#endif

#endif /* AXIS_LIFT_H */
