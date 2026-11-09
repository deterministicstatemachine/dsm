/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Non-secure app memory map. The app is NOT flashed standalone — it is embedded in the Secure
 * monitor image at its own flash region and runs in place from there (dsm-ns-flash.x); only its
 * writable memory is in Non-secure SRAM. Regions + fixed cross-image symbols mirror the monitor's
 * memory.x so both agree on the boundary addresses.
 *
 *   SECURE  [0x20000000, 0x20064000)  monitor (Secure world) — NOT accessible to this app (SAU)
 *   NSC     [0x20064000, 0x20065000)  the single Non-Secure-Callable SG veneer entry
 *   NS      [0x20065000, 0x2007e000)  this app's writable memory: data + bss + heap + stack
 *   MAILBOX [0x2007e000, 0x20080000)  the fixed shared SG mailbox slot (NS RW + S RW; DMA denied)
 *   NSF     [0x10100000, 0x10180000)  this app's image: vectors + code + rodata + data's initial
 *                                     values + a fixed fill to the window end; measured whole
 */
MEMORY {
    NSF : ORIGIN = 0x10100000, LENGTH = 512K
    NS  : ORIGIN = 0x20065000, LENGTH = 100K
}

/* The window the monitor measures, [__ns_rx_start, __ns_rx_end): the whole NSF region, the same
 * constants as the monitor's memory.x. This image fills it exactly with code, read-only data, its
 * data's initial values and a fixed fill; nothing it writes is in it (dsm-ns-flash.x, SA-171). */
__ns_rx_start   = 0x10100000;
__ns_rx_end     = 0x10180000;
__nsc_start     = 0x20064000;
__ns_sram_start = 0x20065000;
__ns_sram_end   = 0x20080000;

/* The single NSC Secure Gateway entry, at the fixed NSC region base (the monitor places the veneer
 * there). The `sg` in the veneer performs the NS->S transition. */
PROVIDE(dsm_secure_dispatch = __nsc_start);

/* The fixed mailbox slot (NS RW + S RW; DMA denied) — same address the monitor reads/writes. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);
