/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor Secure monitor — memory regions + TrustZone domain map.
 * Included by dsm-secure-sram.x (the custom SRAM-resident linker script). The sections themselves
 * live in that script; this file defines only the regions, the fixed domain boundaries, and the
 * executable-policy ASSERTs.
 *
 * §3/§5 TrustZone domain layout (SAU region boundaries the monitor programs at init, step 5):
 *   SECURE  [0x20000000, 0x20040000)  256 KiB  monitor vectors+code+rodata+data+bss+heap+stack
 *   NSC     [0x20040000, 0x20041000)    4 KiB  Non-Secure-Callable (.gnu.sgstubs SG veneer)
 *   NS      [0x20041000, 0x20080000)  ~252 KiB Non-secure app (separate image): RX + RW + mailbox
 * FLASH is storage only: the image lives there and the boot-block LOAD_MAP instructs the immutable
 * bootrom to copy the SRAM-VMA payload into the regions above before entry, because external flash
 * is mutable (a runtime rewrite/glitch must not reach executing Secure code). Cryptographic
 * verification of that flash image is added when secure boot is enabled + validated — separate from
 * the copy the LOAD_MAP describes.
 */
MEMORY {
    FLASH  : ORIGIN = 0x10000000, LENGTH = 4096K   /* storage / LMA only */
    SECURE : ORIGIN = 0x20000000, LENGTH = 256K    /* Secure TCB runtime VMA */
    NSC    : ORIGIN = 0x20040000, LENGTH = 4K      /* Non-Secure-Callable veneer VMA */
    NS     : ORIGIN = 0x20041000, LENGTH = 252K    /* Non-secure app runtime VMA */
}

/* Fixed domain boundaries (shared with the app linker + the signed manifest). */
__secure_sram_start = 0x20000000;
__secure_sram_end   = 0x20040000;
__nsc_start         = 0x20040000;
__nsc_end           = 0x20041000;
__ns_sram_start     = 0x20041000;
__ns_sram_end       = 0x20080000;

/* §3 Non-secure sub-layout: RX (measured, immutable) | RW (data/heap/stack) | fixed mailbox slot.
 * Only the RX range is hashed to mu_enrolled — never data/heap/stack/mailbox. */
__ns_rx_start = __ns_sram_start;
__ns_rx_end   = __ns_sram_start + 0x10000;      /* up to 64 KiB measured RX */
/* One fixed mailbox slot (data plane behind the SG); NS RW + S RW, DMA denied. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);

/* §6 memory proof as executable policy — domain bounds + no overlap + margin (constants only;
 * the symbol-dependent placement ASSERTs live in dsm-secure-sram.x next to the sections). */
ASSERT(__secure_sram_end == ORIGIN(NSC),   "Secure region end must meet the NSC base");
ASSERT(__nsc_end - __nsc_start >= 0x100,    "NSC region too small for the SG veneer stubs");
ASSERT(__secure_sram_end <= __nsc_start,    "Secure / NSC region overlap");
ASSERT(__nsc_end <= __ns_sram_start,        "NSC / Non-secure region overlap");
ASSERT(__ns_rx_end <= (__ns_sram_end - 0x2000), "NS measured RX overruns into the mailbox/RW area");
ASSERT((__ns_sram_end - __secure_sram_start) <= 512K, "SRAM domains exceed 512 KiB");
