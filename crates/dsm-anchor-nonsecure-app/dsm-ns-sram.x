/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * DSM anchor Non-secure app — SRAM-resident linker script (replaces cortex-m-rt's link.x).
 *
 * The Non-secure app is NOT flashed standalone: it is a PAYLOAD embedded in the Secure monitor's
 * image. The monitor's boot-block LOAD_MAP (dsm-secure-sram.x, entry 3) copies this image from the
 * monitor's flash into the Non-secure SRAM region at 0x20041000, and after enabling the SAU the
 * monitor sets MSP_NS + VTOR_NS from this image's 2-word vector table head and BXNS into the reset
 * vector. So the whole image is linked at its Non-secure SRAM VMA (0x20041000); there is no PICOBIN
 * boot block and no self-copy here (the monitor owns the copy). cortex-m-rt's Reset still runs: with
 * VMA == LMA the .data copy is a harmless self-copy and the .bss clear zeroes the NS working set.
 *
 * The vector table's word 0 (initial MSP) and word 1 (reset vector) are exactly what the monitor's
 * launch_nonsecure consumes. The NS stack lives at the top of the usable NS region, just below the
 * fixed shared mailbox slot; it grows down.
 */

INCLUDE memory.x
INCLUDE device.x

EXTERN(__RESET_VECTOR);
EXTERN(Reset);
ENTRY(Reset);

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
  /* NS stack lives at the top of the usable NS region, just below the fixed shared mailbox (the
   * monitor reserves [__ns_sram_end - 0x2000, __ns_sram_end) for DSM_SG_MAILBOX). Grows down. */
  __ns_stack_size = 32K;
  PROVIDE(_stack_start = __ns_sram_end - 0x2000);
  PROVIDE(__ns_stack_limit = (__ns_sram_end - 0x2000) - __ns_stack_size);

  /* ### Vector table — the launch head the monitor consumes (word0 = MSP, word1 = Reset). */
  .vector_table ORIGIN(NS) : ALIGN(4)
  {
    __vector_table = .;
    LONG(_stack_start & 0xFFFFFFF8);
    KEEP(*(.vector_table.reset_vector));
    __exceptions = .;
    KEEP(*(.vector_table.exceptions));
    __eexceptions = .;
    KEEP(*(.vector_table.interrupts));
  } > NS AT> NS

  PROVIDE(_stext = ADDR(.vector_table) + SIZEOF(.vector_table));

  .text _stext : ALIGN(4)
  {
    __stext = .;
    *(.Reset);
    *(.text .text.*);
    *(.HardFaultTrampoline);
    *(.HardFault.*);
    . = ALIGN(4);
    __etext = .;
  } > NS AT> NS

  .rodata : ALIGN(4)
  {
    . = ALIGN(4);
    __srodata = .;
    *(.rodata .rodata.*);
    . = ALIGN(4);
    __erodata = .;
  } > NS AT> NS

  .data : ALIGN(4)
  {
    . = ALIGN(4);
    __sdata = .;
    *(.data .data.*);
    . = ALIGN(4);
  } > NS AT> NS
  . = ALIGN(4);
  __edata = .;
  __sidata = LOADADDR(.data);

  .bss (NOLOAD) : ALIGN(4)
  {
    . = ALIGN(4);
    __sbss = .;
    *(.bss .bss.*);
    *(COMMON);
    . = ALIGN(4);
  } > NS
  . = ALIGN(4);
  __ebss = .;

  .uninit (NOLOAD) : ALIGN(4)
  {
    . = ALIGN(4);
    __suninit = .;
    *(.uninit .uninit.*);
    . = ALIGN(4);
    __euninit = .;
  } > NS
  PROVIDE(__sheap = __euninit);
  PROVIDE(_stack_end = __euninit);

  /* The whole loadable image (vectors+text+rodata+data) is what the monitor copies to NS SRAM. */
  PROVIDE(__ns_image_start = ADDR(.vector_table));
  PROVIDE(__ns_image_end = __edata);

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

ASSERT(ORIGIN(NS) % 8 == 0, "the NS region base must be 8-byte aligned");
ASSERT(__exceptions == ADDR(.vector_table) + 0x8, "BUG: the reset vector is missing");
ASSERT(__eexceptions == ADDR(.vector_table) + 0x40, "BUG: the exception vectors are missing");
ASSERT(SIZEOF(.vector_table) > 0x40, "ERROR: the interrupt vectors are missing");

/* The whole NS TCB must be SRAM-resident (VMA inside the NS region), never flash. */
ASSERT(_stext >= ORIGIN(NS) && _stext < ORIGIN(NS) + LENGTH(NS),
  "ERROR: the Non-secure .text must be SRAM-resident (VMA inside the NS region).");
/* The loadable image + bss/uninit + reserved stack must fit under the mailbox. */
ASSERT(__euninit <= __ns_stack_limit,
  "ERROR: NS .bss/.uninit overruns the reserved NS stack (raise NS size or lower __ns_stack_size).");
