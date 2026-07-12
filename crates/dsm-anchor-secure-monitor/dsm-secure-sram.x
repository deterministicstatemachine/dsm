/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor Secure monitor — SRAM-resident linker script (replaces cortex-m-rt's link.x).
 *
 * WHY a custom script: cortex-m-rt's link.x hard-ASSERTs that .text lives inside FLASH
 * (`_stext > ORIGIN(FLASH) && _stext < ORIGIN(FLASH)+LENGTH(FLASH)`). The Secure TCB must NOT
 * execute from external XIP flash — flash is mutable after the bootrom's boot-time signature check,
 * so a runtime flash rewrite/glitch could substitute Secure instructions. The whole TCB therefore
 * gets a runtime VMA in SRAM with a storage LMA in flash (`AT> FLASH`). The immutable bootrom
 * verifies the signed flash image and copies it to SRAM (via the boot-block LOAD_MAP that picotool
 * derives from these flash-LMA→SRAM-VMA LOAD segments) before entry. A crt0 self-copy is NOT
 * acceptable here (the copier would itself run from mutable flash) — the copy must be the bootrom's.
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
  /* Secure stack lives at the top of the Secure SRAM region (just below the NSC region). */
  PROVIDE(_stack_start = ORIGIN(SECURE) + LENGTH(SECURE));

  /* ## Boot block in FLASH — the bootrom scans the first flash bytes for this signed block. It is
   * the ONLY thing that legitimately resides at the flash runtime address; the payload it points at
   * (below) is copied to SRAM. */
  .start_block ORIGIN(FLASH) : ALIGN(4)
  {
    __start_block_addr = .;
    KEEP(*(.start_block));
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
ASSERT(__nsc_veneer_end <= ORIGIN(NSC) + LENGTH(NSC), "ERROR: SG veneer overruns the NSC region");

ASSERT(SIZEOF(.got) == 0, "ERROR: .got detected — dynamic relocations are not supported");

/* §6 Secure code+rodata size ceiling (SRAM-resident budget from MEMORY_MAP.md). */
ASSERT((__etext - _stext) <= 224K, "Secure monitor code+rodata exceeds the 224 KiB budget (MEMORY_MAP.md)");
