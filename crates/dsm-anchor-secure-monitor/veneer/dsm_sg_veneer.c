// SPDX-License-Identifier: MIT OR Apache-2.0
//
// DSM anchor — Non-Secure-Callable (NSC) Secure Gateway veneer (measurement-seal spec §6, Option C).
//
// This is the ONLY Non-secure -> Secure state transition. It is deliberately tiny: it exports one
// narrow function, begins at a valid SG instruction (emitted by cmse_nonsecure_entry), and does
// nothing but transfer control to the private Secure Rust handler. It exposes NO arbitrary signing
// function, NO raw pointers into Secure memory, and NO HostSign(digest) API.
//
// Build (C CMSE toolchain, cortex-m33):
//     arm-none-eabi-gcc -mcpu=cortex-m33 -mcmse -Os -ffreestanding -c dsm_sg_veneer.c -o dsm_sg_veneer.o
// The cmse_nonsecure_entry stub lands in the .gnu.sgstubs section; the Secure monitor's linker
// script MUST place .gnu.sgstubs entirely inside the linker-defined Non-Secure-Callable region (see
// MEMORY_MAP.md). The generated import library (secure gateway symbols) is what the Non-secure app
// links against — the app never sees the Secure handler, only dsm_secure_dispatch.

#include <stdint.h>
#include <arm_cmse.h>

// Private Secure Rust handler in dsm-anchor-secure-monitor (extern "C"). It performs, entirely in
// Secure state: re-check measurement_ok; validate slot_index + sequence_number; reject oversized /
// misaligned / unknown requests; copy the COMPLETE request from the fixed Non-secure slot into
// Secure SRAM before interpreting it (re-reading no attacker-controlled field after the copy);
// validate the canonical encoding from the Secure copy; execute exactly one of
// status/prepare/commit/emit/finalize/recover; copy a bounded response back to the Non-secure slot;
// zeroize the Secure request copy and sensitive temporaries. The veneer itself does none of this.
extern uint32_t dsm_secure_handler(uint32_t slot_index, uint32_t sequence_number);

// The single NSC entry point. `cmse_nonsecure_entry` emits the SG instruction at the top and, on
// return, the BXNS + register-clearing sequence so no Secure register content leaks back to
// Non-secure. Arguments are scalars only (a fixed-slot index + a sequence number) — never a pointer,
// never a digest. The bulk request/response bytes travel through ONE fixed Non-secure SRAM slot that
// the Secure handler copies in/out; the slot is a data plane, not an authority.
__attribute__((cmse_nonsecure_entry))
uint32_t dsm_secure_dispatch(uint32_t slot_index, uint32_t sequence_number) {
    return dsm_secure_handler(slot_index, sequence_number);
}
