/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor lock image: the RP2350's flash and SRAM, and the boot block in the first 4 KiB of flash
 * where the bootrom looks for it (rp235x-hal's layout). The image runs from flash.
 */
MEMORY {
    FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
    RAM   : ORIGIN = 0x20000000, LENGTH = 512K
}

SECTIONS {
    /* The IMAGE_DEF, after the vector table and inside the first 4 KiB of flash. */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
    } > FLASH
} INSERT AFTER .vector_table;

/* .text starts after the boot block. */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

ASSERT(__start_block_addr < ORIGIN(FLASH) + 4K, "the boot block must sit in the first 4 KiB of flash");
