/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Minimal Non-secure bring-up stub — proves the Secure->Non-secure launch and the NS->S Secure
 * Gateway transition on silicon. It is NOT the production Non-secure app (that is the separate
 * dsm-anchor-nonsecure-app crate); this stub exists only until cross-crate NS packaging lands, and
 * lets the boundary be validated with one self-contained monitor image.
 *
 * Placed by the linker in the .ns_app section at the NS SRAM base (0x20041000) with a FLASH LMA;
 * a LOAD_MAP entry copies it there at boot. The monitor, after SAU, sets MSP_NS + VTOR_NS from this
 * stub's 2-word vector table and BXNS into ns_reset. The stub publishes a STATUS request into the
 * fixed mailbox and calls the NSC veneer dsm_secure_dispatch; the `sg` there transitions to Secure.
 * The Secure handler (bring-up build) self-reboots on that call, which is the observable proof.
 */
    .syntax unified
    .cpu cortex-m33
    .thumb

/* Fixed addresses (must match memory.x / dsm-secure-sram.x). */
    .equ NS_STACK_TOP,  0x2007e000   /* below the mailbox slot at 0x2007e000; grows down */
    .equ VENEER_ENTRY,  0x20040001   /* dsm_secure_dispatch, thumb bit set (NSC region) */
    .equ MAILBOX,       0x2007e000   /* DSM_SG_MAILBOX (= __ns_sram_end - 0x2000) */
    .equ MB_STATE,      0x00         /* Mailbox.state   offset */
    .equ MB_OPCODE,     0x08         /* Mailbox.opcode  offset */
    .equ MB_SEQUENCE,   0x0c         /* Mailbox.sequence offset */
    .equ OP_STATUS,     1
    .equ MB_REQUEST_READY, 1

    .section .ns_app, "ax", %progbits
    .align 3
    .global __ns_app_vector_table
__ns_app_vector_table:
    .word NS_STACK_TOP               /* [0] initial NS MSP */
    .word ns_reset                   /* [1] NS reset vector (.thumb_func already sets bit0) */

    .thumb_func
ns_reset:
    /* Publish a STATUS request into the fixed mailbox (data plane behind the SG). */
    ldr  r3, =MAILBOX
    movs r0, #OP_STATUS
    str  r0, [r3, #MB_OPCODE]
    movs r0, #1
    str  r0, [r3, #MB_SEQUENCE]
    movs r0, #MB_REQUEST_READY
    str  r0, [r3, #MB_STATE]
    dsb
    /* Call the NSC Secure Gateway: dsm_secure_dispatch(slot=0, seq=1). The `sg` in the veneer does
     * the NS->S transition. */
    movs r0, #0
    movs r1, #1
    ldr  r2, =VENEER_ENTRY
    blx  r2
    /* If Secure returns (bring-up handler reboots instead), just spin. */
1:  b    1b
    .pool
