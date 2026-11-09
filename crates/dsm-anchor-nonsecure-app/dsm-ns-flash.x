/* SPDX-License-Identifier: MIT OR Apache-2.0
 *
 * Linker script for the DSM anchor Non-secure app: executed in place from its flash region (NSF),
 * its writable memory in Non-secure SRAM (NS). Replaces cortex-m-rt's link.x so the image has no
 * boot block (the monitor's is the only one the bootrom scans) and fills the measured window exactly.
 *
 * The window [__ns_rx_start, __ns_rx_end) = the whole NSF region holds, in order: the vector table,
 * code, read-only data, the initial values of .data (copied to SRAM by the reset handler), and a
 * fill of trapping words to the window's end. No byte this app writes is in the window (SA-171):
 * .data's VMA, .bss, the heap and the stack are in NS SRAM, below the fixed mailbox slot.
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
  /* The stack sits at the top of NS SRAM, just below the fixed mailbox slot, and grows down. */
  __ns_stack_size = 32K;
  PROVIDE(_stack_start = __ns_sram_end - 0x2000);
  PROVIDE(__ns_stack_limit = (__ns_sram_end - 0x2000) - __ns_stack_size);
  .vector_table ORIGIN(NSF) : ALIGN(4)
  {
    __vector_table = .;
    LONG(_stack_start & 0xFFFFFFF8);
    KEEP(*(.vector_table.reset_vector));
    __exceptions = .;
    KEEP(*(.vector_table.exceptions));
    __eexceptions = .;
    KEEP(*(.vector_table.interrupts));
  } > NSF
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
  } > NSF
  .rodata : ALIGN(4)
  {
    . = ALIGN(4);
    __srodata = .;
    *(.rodata .rodata.*);
    . = ALIGN(4);
    __erodata = .;
  } > NSF
  .data : ALIGN(4)
  {
    . = ALIGN(4);
    __sdata = .;
    *(.data .data.*);
    . = ALIGN(4);
  } > NS AT> NSF
  . = ALIGN(4);
  __edata = .;
  __sidata = LOADADDR(.data);
  __eidata = __sidata + SIZEOF(.data);
  .ns_rx_fill __eidata : ALIGN(4)
  {
    FILL(0xDEDEDEDE);
    . += __ns_rx_end - 4 - __eidata;
    LONG(0xDEDEDEDE);
  } > NSF
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
  PROVIDE(__ns_image_start = ADDR(.vector_table));
  PROVIDE(__ns_image_end = ADDR(.ns_rx_fill) + SIZEOF(.ns_rx_fill));
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
ASSERT(ORIGIN(NSF) % 8 == 0, "the NSF region base must be 8-byte aligned");
ASSERT(__exceptions == ADDR(.vector_table) + 0x8, "BUG: the reset vector is missing");
ASSERT(__eexceptions == ADDR(.vector_table) + 0x40, "BUG: the exception vectors are missing");
ASSERT(SIZEOF(.vector_table) > 0x40, "ERROR: the interrupt vectors are missing");
ASSERT(__eidata <= __ns_rx_end - 4,
  "ERROR: NS code, read-only data and data's initial values overrun the measured window.");
ASSERT(ADDR(.ns_rx_fill) == __eidata, "BUG: a gap between the data's initial values and the window fill");
ASSERT(ADDR(.ns_rx_fill) + SIZEOF(.ns_rx_fill) == __ns_rx_end, "BUG: the window fill misses the window end");
ASSERT(__sidata == __erodata, "BUG: a gap between the read-only data and the data's initial values");
ASSERT(_stext >= ORIGIN(NSF) && _stext < ORIGIN(NSF) + LENGTH(NSF),
  "ERROR: the Non-secure .text must be in the NSF region.");
ASSERT(__sdata >= ORIGIN(NS) && __euninit <= __ns_stack_limit,
  "ERROR: NS .data/.bss/.uninit overrun the reserved NS stack (raise NS size or lower __ns_stack_size).");
ASSERT(SIZEOF(.got) == 0, "ERROR: .got detected — dynamic relocations are not supported");
