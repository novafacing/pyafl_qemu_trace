"""
Events listing for afl-qemu-trace
"""

from enum import Enum


class QEMUEvent(str, Enum):
    """
    QEMU event types
    """

    OUT_ASM = "out_asm"  # show generated host assembly code for each compiled TB
    IN_ASM = "in_asm"  # show target assembly code for each compiled TB
    OP = "op"  # show micro ops for each compiled TB
    OP_OPT = "op_opt"  # show micro ops after optimization
    OP_IND = "op_ind"  # show micro ops before indirect lowering
    INT = "int"  # show interrupts/exceptions in short format
    EXEC = "exec"  # show trace before each executed TB (lots of logs)
    CPU = "cpu"  # show CPU registers before entering a TB (lots of logs)
    FPU = "fpu"  # include FPU registers in the 'cpu' logging
    MMU = "mmu"  # log MMU-related activities
    PCALL = "pcall"  # x86 only: show protected mode far calls/returns/exceptions
    CPU_RESET = "cpu_reset"  # show CPU state before CPU resets
    UNIMP = "unimp"  # log unimplemented functionality
    GUEST_ERRORS = (
        "guest_errors"  # log when the guest OS does something invalid (eg accessing a
    )
    # non-existent register)
    PAGE = "page"  # dump pages at beginning of user mode emulation
    NOCHAIN = "nochain"  # do not chain compiled TBs so that "exec" and "cpu" show
    # complete traces
    STRACE = "strace"  # log every user-mode syscall, its input, and its result
