/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor Secure monitor — memory regions + TrustZone domain map.
 * Included by dsm-secure-sram.x (the custom SRAM-resident linker script). The sections themselves
 * live in that script; this file defines only the regions, the fixed domain boundaries, and the
 * executable-policy ASSERTs.
 *
 * §3/§5 TrustZone domain layout (SAU region boundaries the monitor programs at init, step 5):
 *   SECURE  [0x20000000, 0x20064000)  400 KiB  monitor vectors+code+rodata+data+bss+heap+stack
 *   NSC     [0x20064000, 0x20065000)    4 KiB  Non-Secure-Callable (.gnu.sgstubs SG veneer)
 *   NS      [0x20065000, 0x20080000)  108 KiB  Non-secure app writable memory: data, bss, heap,
 *                                              stack, and the fixed mailbox slot at its end
 *   NSF     [0x10100000, 0x10180000)  512 KiB  Non-secure app image, executed in place from flash:
 *                                              vectors, code, read-only data (the radio's firmware
 *                                              among it), the initial values of its data, and a
 *                                              trapping fill to the window's end. The whole region
 *                                              is the measured window.
 * FLASH is the Secure image's storage only: the boot-block LOAD_MAP instructs the immutable bootrom
 * to copy the SRAM-VMA payload into the SRAM regions above before entry, because external flash is
 * mutable (a runtime rewrite/glitch must not reach executing Secure code). The Non-secure image
 * stays in flash (LOAD_MAP entry 3 has equal storage and runtime addresses: the bootrom hashes it
 * and copies nothing), and the monitor measures it fresh before every authority operation.
 */
MEMORY {
    FLASH  : ORIGIN = 0x10000000, LENGTH = 1024K   /* Secure image storage / LMA only */
    NSF    : ORIGIN = 0x10100000, LENGTH = 512K    /* Non-secure image, executed in place */
    SECURE : ORIGIN = 0x20000000, LENGTH = 400K    /* Secure TCB runtime VMA */
    NSC    : ORIGIN = 0x20064000, LENGTH = 4K      /* Non-Secure-Callable veneer VMA */
    NS     : ORIGIN = 0x20065000, LENGTH = 108K    /* Non-secure app writable memory */
}

/* Fixed domain boundaries (shared with the app linker + the signed manifest). */
__secure_sram_start = 0x20000000;
__secure_sram_end   = 0x20064000;
__nsc_start         = 0x20064000;
__nsc_end           = 0x20065000;
__ns_sram_start     = 0x20065000;
__ns_sram_end       = 0x20080000;
__ns_flash_start    = 0x10100000;
__ns_flash_end      = 0x10180000;

/* §3 Non-secure sub-layout: the measured window is the whole flash image region (code, read-only
 * data, data's initial values, fixed fill); Non-secure SRAM is RW (data/bss/heap/stack) with the
 * fixed mailbox slot at its end. Only the flash window is hashed to mu_enrolled — never SRAM. */
__ns_rx_start = __ns_flash_start;
__ns_rx_end   = __ns_flash_end;
/* One fixed mailbox slot (data plane behind the SG); NS RW + S RW, DMA denied. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);

/* §6 memory proof as executable policy — domain bounds + no overlap + margin (constants only;
 * the symbol-dependent placement ASSERTs live in dsm-secure-sram.x next to the sections). */
ASSERT(__secure_sram_end == ORIGIN(NSC),   "Secure region end must meet the NSC base");
ASSERT(__nsc_end - __nsc_start >= 0x100,    "NSC region too small for the SG veneer stubs");
ASSERT(__secure_sram_end <= __nsc_start,    "Secure / NSC region overlap");
ASSERT(__nsc_end <= __ns_sram_start,        "NSC / Non-secure region overlap");
ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) <= ORIGIN(NSF), "Secure image storage overruns the Non-secure flash image");
ASSERT(__ns_rx_start == ORIGIN(NSF) && __ns_rx_end == ORIGIN(NSF) + LENGTH(NSF), "the measured window is the whole Non-secure flash region");
ASSERT((__ns_sram_end - __secure_sram_start) <= 512K, "SRAM domains exceed 512 KiB");
