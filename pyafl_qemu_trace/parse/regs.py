"""
Constant regexes for the trace parser
"""

from re import compile  # pylint: disable=redefined-builtin

# Regex to match the lines in an output that contain the traced addresses
TRACE_RE = compile(
    rb"Trace\s+(?P<trace_number>[0-9]+):\s+(?P<host_addr>0x[0-9a-fA-F]+)\s+"
    rb"\[(?P<flags1>[0-9a-fA-F]+)"
    rb"\/(?P<guest_addr>[0-9a-fA-F]+)"
    rb"\/(?P<flags2>0x[0-9a-fA-F]+)\]"
)

# Regex to match memory mapping changes in the output
MMAP_RE = compile(
    # Header ------------------------------------------------------
    rb"start\s+end\s+size\s+prot\n"
    # Start-End ---------------------------------------------------
    rb"(?:(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)"
    # Size Prot ---------------------------------------------------
    rb"\s+(?P<size>[0-9a-fA-F]+)\s+(?P<prot>[rwx-]+)[\n]?)+"
)

MMAP_LINE_RE = compile(
    rb"(?:(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)"
    # Size Prot ---------------------------------------------------
    rb"\s+(?P<size>[0-9a-fA-F]+)\s+(?P<prot>[rwx-]+)[\n]?)"
)

STRACE_RE = compile(
    rb"(?P<syscall_num>[0-9]+)\s+(?P<syscall_name>\w+)\((?P<syscall_args>[^\)]*)\)"
    rb"(?P<syscall_output>[^=]|\n)*=\s*(?P<syscall_ret>[-]?[0-9]+)"
    rb"(\s?errno\s?=\s?(?P<syscall_errno>[-]?[0-9]+)\s?\((?P<syscall_errmsg>[^\)]+)\))?"
)

MAPPING_RES = {
    "guest_base": compile(rb"guest_base\s+0x(?P<guest_base>[0-9a-fA-F]+)"),
    "start_brk": compile(rb"start_brk\s+0x(?P<start_brk>[0-9a-fA-F]+)"),
    "start_code": compile(rb"start_code\s+0x(?P<start_code>[0-9a-fA-F]+)"),
    "end_code": compile(rb"end_code\s+0x(?P<end_code>[0-9a-fA-F]+)"),
    "start_data": compile(rb"start_data\s+0x(?P<start_data>[0-9a-fA-F]+)"),
    "end_data": compile(rb"end_data\s+0x(?P<end_data>[0-9a-fA-F]+)"),
    "start_stack": compile(rb"start_stack\s+0x(?P<start_stack>[0-9a-fA-F]+)"),
    "brk": compile(rb"brk\s+0x(?P<brk>[0-9a-fA-F]+)"),
    "entry": compile(rb"entry\s+0x(?P<entry>[0-9a-fA-F]+)"),
    "argv_start": compile(rb"argv_start\s+0x(?P<argv_start>[0-9a-fA-F]+)"),
    "env_start": compile(rb"env_start\s+0x(?P<env_start>[0-9a-fA-F]+)"),
    "auxv_start": compile(rb"auxv_start\s+0x(?P<auxv_start>[0-9a-fA-F]+)"),
}
