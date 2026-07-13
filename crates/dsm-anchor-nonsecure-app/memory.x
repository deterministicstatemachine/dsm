MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8 : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9 : ORIGIN = 0x20081000, LENGTH = 4K
}

/*
 * Non-secure image — the Secure monitor loads + measures this image's RX range into Non-secure SRAM
 * (step 7). These cross-image symbols mirror the monitor's memory.x layout so both agree on the
 * fixed addresses; the two-image integration reconciles the veneer's real NSC address.
 */
__nsc_start     = 0x20040000;
__ns_sram_start = 0x20041000;
__ns_sram_end   = 0x20080000;

/* The single NSC Secure Gateway entry, resolved at the fixed NSC region base (the monitor places
 * the veneer stub here in the SRAM-image layout). PROVIDE lets the app link standalone this increment. */
PROVIDE(dsm_secure_dispatch = __nsc_start);
/* The fixed mailbox slot (NS RW + S RW; DMA denied) — same address the monitor reads/writes. */
PROVIDE(DSM_SG_MAILBOX = __ns_sram_end - 0x2000);

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
