/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Non-secure app memory map. The app is NOT flashed standalone — it is embedded in the Secure
 * monitor image and copied into the Non-secure SRAM region by the monitor's LOAD_MAP, so the whole
 * app is linked at its Non-secure SRAM VMA (see dsm-ns-sram.x). Regions + fixed cross-image symbols
 * mirror the monitor's memory.x so both agree on the boundary addresses.
 *
 *   SECURE  [0x20000000, 0x20040000)  monitor (Secure world) — NOT accessible to this app (SAU)
 *   NSC     [0x20040000, 0x20041000)  the single Non-Secure-Callable SG veneer entry
 *   NS      [0x20041000, 0x2007e000)  this app: vectors + code + rodata + data + bss + stack
 *   MAILBOX [0x2007e000, 0x20080000)  the fixed shared SG mailbox slot (NS RW + S RW; DMA denied)
 */
MEMORY {
    NS : ORIGIN = 0x20041000, LENGTH = 244K
}

__nsc_start     = 0x20040000;
__ns_sram_start = 0x20041000;
__ns_sram_end   = 0x20080000;

/* The single NSC Secure Gateway entry, at the fixed NSC region base (the monitor places the veneer
 * there). The `sg` in the veneer performs the NS->S transition. */
PROVIDE(dsm_secure_dispatch = __nsc_start);
/* The fixed mailbox slot (NS RW + S RW; DMA denied) — same address the monitor reads/writes. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);
