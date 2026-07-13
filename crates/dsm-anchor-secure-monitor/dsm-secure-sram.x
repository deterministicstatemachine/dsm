/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor Secure monitor — SRAM-resident linker script (replaces cortex-m-rt's link.x).
 *
 * WHY a custom script: cortex-m-rt's link.x hard-ASSERTs that .text lives inside FLASH
 * (`_stext > ORIGIN(FLASH) && _stext < ORIGIN(FLASH)+LENGTH(FLASH)`). The Secure TCB must NOT
 * execute from external XIP flash — flash is mutable, so a runtime flash rewrite/glitch could
 * substitute Secure instructions. The whole TCB therefore gets a runtime VMA in SRAM with a storage
 * LMA in flash (`AT> FLASH`). The boot-block LOAD_MAP instructs the immutable bootrom to copy the
 * flash payload to SRAM before entry. A crt0 self-copy is NOT acceptable (the copier would itself
 * run from mutable flash) — the copy must be the bootrom's. Cryptographic verification of the flash
 * image is a SEPARATE property added when secure boot is enabled + validated; the LOAD_MAP only
 * describes the copy.
 *
 * This script mirrors cortex-m-rt's link.x.in section-for-section, changing only the placement of
 * the executable/rodata/data/vectors from FLASH to the SECURE SRAM region, dropping the
 * flash-residency ASSERT, and fixing the NSC veneer at the SAU NSC region base.
 *
 * STATUS: the ELF layout (SRAM VMA / flash LMA / SRAM entry) is host-verifiable via readelf/nm and
 * check-secure-no-xip.sh. The bootrom actually honoring the LOAD_MAP + secure-boot verification is
 * confirmed only on silicon (checkpoint step 6). Do not claim silicon behavior from a host build.
 */

INCLUDE memory.x

/* Device interrupt weak aliases (rp235x-pac emits device.x → PROVIDE(<IRQ> = DefaultHandler)).
 * cortex-m-rt's link.x includes this; the custom script must too, or every device IRQ vector is an
 * undefined symbol. */
INCLUDE device.x

/* # Entry point = reset vector */
EXTERN(__RESET_VECTOR);
EXTERN(Reset);
ENTRY(Reset);

/* # Exception vectors (weak-aliased at the linker level; overridable via cortex-m-rt macros) */
EXTERN(__EXCEPTIONS);
EXTERN(DefaultHandler);

PROVIDE(NonMaskableInt = DefaultHandler);
EXTERN(HardFaultTrampoline);
PROVIDE(MemoryManagement = DefaultHandler);
PROVIDE(BusFault = DefaultHandler);
PROVIDE(UsageFault = DefaultHandler);
PROVIDE(SecureFault = DefaultHandler);
PROVIDE(SVCall = DefaultHandler);
PROVIDE(DebugMonitor = DefaultHandler);
PROVIDE(PendSV = DefaultHandler);
PROVIDE(SysTick = DefaultHandler);

PROVIDE(DefaultHandler = DefaultHandler_);
PROVIDE(HardFault = HardFault_);

EXTERN(__INTERRUPTS);

PROVIDE(__pre_init = DefaultPreInit);

SECTIONS
{
  PROVIDE(_ram_start = ORIGIN(SECURE));
  PROVIDE(_ram_end = ORIGIN(SECURE) + LENGTH(SECURE));
  /* Secure stack lives at the top of the Secure SRAM region (just below the NSC region) and grows
   * DOWN. __secure_stack_limit is its explicit floor: MSPLIM is set to it (ENTRY_POINT sp_limit
   * word + belt-and-suspenders write at reset) so a Secure stack overflow FAULTS instead of
   * silently corrupting the monitor's own code/state/heap below it.
   * Sized to fit the SRAM-resident TCB: SECURE (256K) = ~137K code+rodata + 56K working heap
   * (SPHINCS+ σ^host) + this 48K stack. SILICON (SWD, 2026-07-13): the appliance bring-up call
   * chain — TROPIC01 session_start (X25519 DH + AES-GCM + SHA-256) plus the ~4.6K `Tropic01`
   * (ActiveSession) struct move — overflowed a 20K stack (read CFSR.STKOF over SWD, SP just above
   * the 20K MSPLIM); 48K clears it (CFSR=0, init runs to completion). The MSPLIM floor sits above
   * `.bss`, so any future overflow faults (caught by the Secure fault handler), never corrupts. */
  __secure_stack_size = 48K;
  PROVIDE(_stack_start = ORIGIN(SECURE) + LENGTH(SECURE));
  PROVIDE(__secure_stack_limit = ORIGIN(SECURE) + LENGTH(SECURE) - __secure_stack_size);

  /* ## Boot block in FLASH — the bootrom scans the first flash bytes for this block. It is the ONLY
   * thing that legitimately runs from the flash address; the payload it maps (below) is copied to
   * SRAM. The whole PICOBIN block is emitted here by the linker (LMA/VMA/size are link-time values).
   *
   * PICOBIN item encodings (rp235x-hal block.rs):
   *   1BS item word = (value<<16)|(size_words<<8)|type ;  2BS item word = (value<<24)|(size_words<<8)|type
   * Relative LOAD_MAP entry (Raspberry Pi picobin) = 3 words:
   *   (source_LMA - address_of_LOAD_MAP_item) , runtime_VMA , byte_size
   *   A zero source means "clear the runtime region" (BSS/scratch zero-fill).
   * LOAD_MAP header = (n_entries<<24) | ((1 + 3*n_entries)<<8) | 0x06. */
  .start_block ORIGIN(FLASH) : ALIGN(4)
  {
    __start_block_addr = .;
    LONG(0xffffded3);                                  /* BLOCK_MARKER_START */

    /* IMAGE_TYPE (1BS 0x42): EXE(0x0001)|RP2350(0x1000)|ARM(0x0000)|SECURITY_S(0x0020)=0x1021 */
    LONG((0x1021 << 16) | (1 << 8) | 0x42);

    /* LOAD_MAP (2BS 0x06): 4 entries, size = 1 + 3*4 = 13 words. */
    __dsm_load_map = .;
    LONG((4 << 24) | (13 << 8) | 0x06);
    /* entry 1 — contiguous low Secure image (vectors+.text+.rodata+.data) FLASH -> SRAM 0x20000000 */
    LONG(LOADADDR(.vector_table) - __dsm_load_map);
    LONG(ADDR(.vector_table));
    LONG((LOADADDR(.data) + SIZEOF(.data)) - LOADADDR(.vector_table));
    /* entry 2 — NSC SG veneer FLASH -> SRAM 0x20040000 */
    LONG(LOADADDR(.gnu.sgstubs) - __dsm_load_map);
    LONG(ADDR(.gnu.sgstubs));
    LONG(SIZEOF(.gnu.sgstubs));
    /* entry 3 — Non-secure app image (bring-up stub) FLASH -> NS SRAM 0x20041000 */
    LONG(LOADADDR(.ns_app) - __dsm_load_map);
    LONG(ADDR(.ns_app));
    LONG(SIZEOF(.ns_app));
    /* entry 4 — zero-fill Secure .bss (source 0 = clear); immutable bootrom clears it, not crt0 */
    LONG(0);
    LONG(__sbss);
    LONG(__ebss - __sbss);

    /* VECTOR_TABLE (1BS 0x03, 2 words): runtime VTOR = SRAM vector table. */
    LONG((0 << 16) | (2 << 8) | 0x03);
    LONG(ADDR(.vector_table));

    /* ENTRY_POINT (1BS 0x44, 4 words): PC (Reset, thumb bit) + initial SP + SP limit (MSPLIM). The
     * optional 4th word makes the bootrom arm the Secure stack guard before entry. */
    LONG((0 << 16) | (4 << 8) | 0x44);
    LONG(Reset | 1);
    LONG(_stack_start);
    LONG(__secure_stack_limit);

    /* LAST item (2BS 0xff): size field = total item words above = 1+13+2+4 = 20. */
    LONG((20 << 8) | 0xff);
    LONG(0);                                           /* block-loop offset: 0 = single-block self-loop */
    LONG(0xab123579);                                  /* BLOCK_MARKER_END */

    KEEP(*(.boot_info));
  } > FLASH

  /* ## Runtime image in SRAM (VMA), stored in FLASH (LMA). */
  /* ### Vector table — runtime VTOR target, in SRAM. */
  .vector_table ORIGIN(SECURE) : ALIGN(4)
  {
    __vector_table = .;
    LONG(_stack_start & 0xFFFFFFF8);
    KEEP(*(.vector_table.reset_vector));
    __exceptions = .;
    KEEP(*(.vector_table.exceptions));
    __eexceptions = .;
    KEEP(*(.vector_table.interrupts));
  } > SECURE AT> FLASH

  PROVIDE(_stext = ADDR(.vector_table) + SIZEOF(.vector_table));

  /* ### .text */
  .text _stext : ALIGN(4)
  {
    __stext = .;
    *(.Reset);
    *(.text .text.*);
    *(.HardFaultTrampoline);
    *(.HardFault.*);
    . = ALIGN(4);
    __etext = .;
  } > SECURE AT> FLASH

  /* ### .rodata */
  .rodata : ALIGN(4)
  {
    . = ALIGN(4);
    __srodata = .;
    *(.rodata .rodata.*);
    . = ALIGN(4);
    __erodata = .;
  } > SECURE AT> FLASH

  /* ### .data — VMA in SRAM, LMA in FLASH (cortex-m-rt's Reset also copies this; harmless when the
   * bootrom LOAD_MAP already staged it). */
  .data : ALIGN(4)
  {
    . = ALIGN(4);
    __sdata = .;
    *(.data .data.*);
    . = ALIGN(4);
  } > SECURE AT> FLASH
  . = ALIGN(4);
  __edata = .;
  __sidata = LOADADDR(.data);

  /* ### .gnu.sgstubs — the NSC Secure Gateway veneer, fixed at the SAU NSC region base so the
   * Non-secure app's imported `dsm_secure_dispatch` address matches (checkpoint step 4). SRAM VMA,
   * FLASH LMA. SAU regions require 32-byte alignment; the NSC base is 32-aligned. */
  .gnu.sgstubs ORIGIN(NSC) : ALIGN(32)
  {
    . = ALIGN(32);
    __nsc_veneer_start = .;
    __veneer_base = .;
    *(.gnu.sgstubs .gnu.sgstubs.*)
    . = ALIGN(32);
    __nsc_veneer_end = .;
  } > NSC AT> FLASH
  . = ALIGN(32);
  __veneer_limit = .;

  /* ### .ns_app — the Non-secure bring-up stub, VMA at the NS SRAM base (0x20041000), FLASH LMA.
   * A LOAD_MAP entry copies it to NS SRAM; the monitor launches it Non-secure after SAU. Replaced
   * by the real dsm-anchor-nonsecure-app image once cross-crate NS packaging lands. */
  .ns_app ORIGIN(NS) : ALIGN(8)
  {
    __ns_app_start = .;
    KEEP(*(.ns_app .ns_app.*))
    . = ALIGN(4);
    __ns_app_end = .;
  } > NS AT> FLASH

  /* ### .bss */
  .bss (NOLOAD) : ALIGN(4)
  {
    . = ALIGN(4);
    __sbss = .;
    *(.bss .bss.*);
    *(COMMON);
    . = ALIGN(4);
  } > SECURE
  . = ALIGN(4);
  __ebss = .;

  /* ### .uninit */
  .uninit (NOLOAD) : ALIGN(4)
  {
    . = ALIGN(4);
    __suninit = .;
    *(.uninit .uninit.*);
    . = ALIGN(4);
    __euninit = .;
  } > SECURE
  PROVIDE(__sheap = __euninit);
  PROVIDE(_stack_end = __euninit);

  /* ## picotool 'Binary Info' entries — kept in FLASH (metadata, not executed). */
  .bi_entries : ALIGN(4)
  {
    __bi_entries_start = .;
    KEEP(*(.bi_entries));
    . = ALIGN(4);
    __bi_entries_end = .;
  } > FLASH

  /* ## End block in FLASH (closes the boot-block chain). */
  .end_block : ALIGN(4)
  {
    __end_block_addr = .;
    KEEP(*(.end_block));
    __flash_binary_end = .;
  } > FLASH

  PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
  PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

  /* ## .got — dynamic relocation detector (must stay empty). */
  .got (NOLOAD) :
  {
    KEEP(*(.got .got.*));
  }

  /DISCARD/ :
  {
    *(.ARM.exidx);
    *(.ARM.exidx.*);
    *(.ARM.extab.*);
  }
}

/* # Alignment checks (from cortex-m-rt). */
ASSERT(ORIGIN(FLASH) % 4 == 0, "the start of the FLASH region must be 4-byte aligned");
ASSERT(ORIGIN(SECURE) % 4 == 0, "the start of the SECURE SRAM region must be 4-byte aligned");
ASSERT(__sdata % 4 == 0 && __edata % 4 == 0, "BUG: .data is not 4-byte aligned");
ASSERT(__sidata % 4 == 0, "BUG: the LMA of .data is not 4-byte aligned");
ASSERT(__sbss % 4 == 0 && __ebss % 4 == 0, "BUG: .bss is not 4-byte aligned");
ASSERT(__sheap % 4 == 0, "BUG: start of .heap is not 4-byte aligned");
ASSERT(_stack_start % 8 == 0, "the stack start address is not 8-byte aligned");

/* # Position checks. */
ASSERT(__exceptions == ADDR(.vector_table) + 0x8, "BUG: the reset vector is missing");
ASSERT(__eexceptions == ADDR(.vector_table) + 0x40, "BUG: the exception vectors are missing");
ASSERT(SIZEOF(.vector_table) > 0x40, "ERROR: the interrupt vectors are missing");

/* The whole executable TCB must be SRAM-resident: _stext lives in the SECURE SRAM region, NOT flash.
 * This is the inverse of cortex-m-rt's flash-residency ASSERT and is the executable form of the
 * security requirement. */
ASSERT(_stext >= ORIGIN(SECURE) && _stext < ORIGIN(SECURE) + LENGTH(SECURE),
  "ERROR: the Secure .text must be SRAM-resident (VMA inside the SECURE region), not XIP flash.");

/* The measured/runtime image must fit under the NSC region so the stack + Secure data have room. */
ASSERT(__euninit <= ORIGIN(NSC), "ERROR: Secure runtime image (text+rodata+data+bss+uninit) overruns into the NSC region");
/* The reserved Secure stack must not overlap bss/uninit/heap below it (MSPLIM guards the other end). */
ASSERT(__euninit <= __secure_stack_limit, "ERROR: Secure .bss/.uninit/heap collides with the reserved Secure stack region (raise SECURE size or lower __secure_stack_size)");
ASSERT(__nsc_veneer_end <= ORIGIN(NSC) + LENGTH(NSC), "ERROR: SG veneer overruns the NSC region");

ASSERT(SIZEOF(.got) == 0, "ERROR: .got detected — dynamic relocations are not supported");

/* §6 Secure code+rodata size ceiling (SRAM-resident budget from MEMORY_MAP.md). */
ASSERT((__etext - _stext) <= 224K, "Secure monitor code+rodata exceeds the 224 KiB budget (MEMORY_MAP.md)");
