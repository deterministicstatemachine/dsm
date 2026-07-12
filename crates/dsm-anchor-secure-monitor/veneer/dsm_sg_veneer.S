/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor — reviewed ARMv8-M assembly NSC Secure Gateway veneer (spec §6, Option C, path 2).
 *
 * The C `-mcmse` path did not interoperate with rust-lld's --cmse-implib symbol convention, so this
 * is the sanctioned small reviewed asm veneer. It defines the single Non-Secure-Callable entry
 * `dsm_secure_dispatch` directly in `.gnu.sgstubs` (placed in the linker-defined NSC region by
 * memory.x). It begins with the `sg` instruction (a valid Secure Gateway entry), tail-transfers into
 * the private Secure handler, then — CRITICAL for security — scrubs every caller-saved register and
 * the FP context that could hold Secure state before `bxns` returns to Non-secure, so no Secure data
 * leaks across the boundary. Only r0 (the u32 status) is returned.
 *
 * SECURITY REVIEW REQUIRED BEFORE SILICON: confirm the caller-saved scrub set is complete for the
 * exact ABI the Secure handler is built with (integer r1-r3,r12 + APSR; FP s0-s15 + FPSCR on this
 * hardfloat target). This veneer is deliberately tiny so it can be reviewed in full.
 *
 * Build: clang --target=arm-none-eabi -mcpu=cortex-m33 -mfloat-abi=hard -c dsm_sg_veneer.S
 * The Non-secure app resolves `dsm_secure_dispatch` at the fixed NSC region base (no --cmse-implib).
 */
    .syntax unified
    .cpu cortex-m33
    .fpu fpv5-sp-d16
    .thumb

    .extern dsm_secure_handler          /* the private Secure Rust handler */

    .section .gnu.sgstubs, "ax", %progbits
    .align  5
    .global dsm_secure_dispatch
    .thumb_func
    .type   dsm_secure_dispatch, %function
dsm_secure_dispatch:
    sg                                  /* Secure Gateway: the ONLY valid NS->S entry instruction */
    push    {r4, lr}
    bl      dsm_secure_handler          /* (r0=slot_index, r1=sequence_number) -> r0 = status */
    pop     {r4, lr}

    /* ── scrub caller-saved state before returning to Non-secure (no Secure leak) ── */
    movs    r1, #0
    movs    r2, #0
    movs    r3, #0
    mov     r12, #0
    /* FP caller-saved regs s0-s15 + FPSCR (hardfloat target may pass secrets through them) */
    vmov    s0, r1
    vmov    s1, r1
    vmov    s2, r1
    vmov    s3, r1
    vmov    s4, r1
    vmov    s5, r1
    vmov    s6, r1
    vmov    s7, r1
    vmov    s8, r1
    vmov    s9, r1
    vmov    s10, r1
    vmov    s11, r1
    vmov    s12, r1
    vmov    s13, r1
    vmov    s14, r1
    vmov    s15, r1
    vmsr    fpscr, r1
    /* clear the condition/GE flags */
    msr     APSR_nzcvqg, r1
    bxns    lr                          /* return to Non-secure, clearing the security state */
    .size   dsm_secure_dispatch, . - dsm_secure_dispatch
