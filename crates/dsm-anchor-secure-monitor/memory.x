MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

/*
 * §3/§5 TrustZone domain layout — fixed addresses shared by the monitor + app linker scripts and the
 * signed manifest. These are the SAU region boundaries the monitor programs at init (step 5).
 * Secure occupies the low SRAM; the NSC veneer region and the Non-secure image occupy the high SRAM.
 *
 * IMPORTANT — this is the TARGET layout, NOT the current image. cortex-m-rt's link.x forces .text
 * into FLASH (it ASSERTs _stext is inside the FLASH region), so the monitor currently links + runs
 * as an XIP-flash image and check-secure-no-xip.sh FAILS. Making the TCB actually SRAM-resident
 * requires replacing cortex-m-rt's linker with a custom Secure script (SRAM VMA / flash LMA) plus a
 * bootrom LOAD_MAP so the immutable bootrom verifies the signed flash image and copies it to SRAM
 * before entry. Until that lands, treat these boundaries as the intended map, not live residency.
 */
__secure_sram_start = 0x20000000;
__secure_sram_end   = 0x20040000;   /* 256 KiB Secure (monitor code+data+heap+stack) — TARGET VMA */
__nsc_start         = 0x20040000;
__nsc_end           = 0x20041000;   /* 4 KiB Non-Secure-Callable (SG veneers / .gnu.sgstubs) */
__ns_sram_start     = 0x20041000;
__ns_sram_end       = 0x20080000;   /* ~252 KiB Non-secure (app RX + RW + heap + stack + mailbox) */

/*
 * §3 Non-secure sub-layout: RX (measured, immutable) | RW (data/heap/stack) | fixed mailbox slot.
 * Only the RX range is hashed to mu_enrolled — never data/heap/stack/mailbox. The app linker fixes
 * the exact RX end; these are the reserved bounds.
 */
__ns_rx_start = __ns_sram_start;
__ns_rx_end   = __ns_sram_start + 0x10000;      /* up to 64 KiB measured RX */
/* One fixed mailbox slot (data plane behind the SG); NS RW + S RW, DMA denied. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);

/* §6 memory proof as executable policy — linker assertions (domain bounds + no overlap + margin). */
ASSERT(__nsc_end - __nsc_start >= 0x100,   "NSC region too small for the SG veneer stubs");
ASSERT(__secure_sram_end <= __nsc_start,   "Secure / NSC region overlap");
ASSERT(__nsc_end <= __ns_sram_start,       "NSC / Non-secure region overlap");
ASSERT(__ns_rx_end <= (__ns_sram_end - 0x2000), "NS measured RX overruns into the mailbox/RW area");
ASSERT((__ns_sram_end - __secure_sram_start) <= 512K, "SRAM domains exceed 512 KiB");

SECTIONS {
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH
} INSERT AFTER .vector_table;

_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    .bi_entries : ALIGN(4)
    {
        __bi_entries_start = .;
        KEEP(*(.bi_entries));
        . = ALIGN(4);
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

/*
 * The NSC Secure Gateway veneer (.gnu.sgstubs). This increment places it in FLASH so the monitor
 * links; the SRAM-image linker step relocates the whole TCB (incl. this stub) into the fixed NSC
 * SRAM region [__nsc_start, __nsc_end) so check-secure-no-xip.sh passes.
 */
SECTIONS {
    .gnu.sgstubs : ALIGN(32)
    {
        __nsc_veneer_start = .;
        KEEP(*(.gnu.sgstubs .gnu.sgstubs.*))
        . = ALIGN(4);
        __nsc_veneer_end = .;
    } > FLASH
} INSERT AFTER .text;

/* §6 the SG veneer must fit inside the reserved NSC region. */
ASSERT((__nsc_veneer_end - __nsc_veneer_start) <= (__nsc_end - __nsc_start),
       "SG veneer (.gnu.sgstubs) exceeds the reserved NSC region size");

SECTIONS {
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
        __flash_binary_end = .;
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/* §6 Secure image size ceiling (code+rodata SRAM-resident budget from MEMORY_MAP.md). */
ASSERT((__etext - _stext) <= 224K, "Secure monitor code+rodata exceeds the 224 KiB budget (MEMORY_MAP.md)");
