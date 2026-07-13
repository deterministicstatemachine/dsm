/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Non-secure app PAYLOAD: embeds the real dsm-anchor-nonsecure-app SRAM image (built + objcopy'd to
 * ns_app.bin by build.rs) into the monitor's .ns_app section. Replaces the old bring-up stub
 * (dsm_ns_stub.S) now that cross-crate NS packaging is wired.
 *
 * The linker places .ns_app at the NS SRAM base (0x20041000) with a FLASH LMA; the monitor's
 * LOAD_MAP entry 3 copies it there at boot, then BXNS into __ns_app_vector_table (word 0 = NS MSP,
 * word 1 = NS reset). Those bytes ARE the NS app's own vector table, so the symbol just names the
 * image start. build.rs passes -I <OUT_DIR> so `.incbin` finds ns_app.bin.
 */
    .section .ns_app, "ax", %progbits
    .align 3
    .global __ns_app_vector_table
__ns_app_vector_table:
    .incbin "ns_app.bin"
