"""
Utilities for parsing afl qemu trace logs
"""

from array import array
from collections import defaultdict
from functools import partial
from pathlib import Path
from re import compile, Match, finditer
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
    TypeVar,
    Callable,
    Iterator,
)
from attr import define, field

base16 = partial(int, base=16)

TRACE_RE = compile(
    rb"Trace\s+(?P<trace_number>[0-9]+):\s+(?P<host_addr>0x[0-9a-fA-F]+)\s+"
    rb"\[(?P<flags1>[0-9a-fA-F]+)"
    rb"\/(?P<guest_addr>[0-9a-fA-F]+)"
    rb"\/(?P<flags2>0x[0-9a-fA-F]+)\]"
)

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

V = TypeVar("V")


@define(frozen=True, slots=True)
class MMap:
    """
    Memory mapping
    """

    start: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    end: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    size: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    prot: bytes


@define(frozen=True, slots=True)
class Syscall:
    """
    Simple descriptor of a syscall
    """

    name: bytes
    ret: int = field(converter=int)
    args: List[bytes] = field(factory=list)
    errno: Optional[int] = field(
        default=None, converter=lambda x: int(x) if x else None
    )
    err: Optional[bytes] = None


@define(slots=True)
class TraceResult:
    """
    Result of a trace
    """

    # Straight up list of addresses
    addrs: array
    # Mapping of index in addrs: list of mmaps in the mapping output at that last index before
    # the mapping
    maps: Dict[int, Set[MMap]]
    # Mapping of the index in addrs: syscall at that last index before the syscall
    syscalls: Dict[int, Syscall]
    # Mapping information
    guest_base: Optional[int] = None
    start_brk: Optional[int] = None
    start_code: Optional[int] = None
    end_code: Optional[int] = None
    start_data: Optional[int] = None
    end_data: Optional[int] = None
    start_stack: Optional[int] = None
    brk: Optional[int] = None
    entry: Optional[int] = None
    argv_start: Optional[int] = None
    env_start: Optional[int] = None
    auxv_start: Optional[int] = None
    mmap_min: Optional[int] = None


def interleave_lambda_longest(func: Callable, *args: Iterable[V]) -> Iterator[V]:
    """
    Interleave from a collection of iterables until all are exhausted
    by repeatedly calling `f` with the set of non-exhausted iterators to
    determine the next iterator to iterate.
    """

    iterators = list(map(iter, args))  # type: ignore

    values: List[Optional[V]] = []

    for i in iterators:
        try:
            values.append(next(i))
        except StopIteration:
            values.append(None)

    while any(map(lambda v: v is not None, values)):
        idx = func(*values)

        if values[idx] is not None:
            yield values[idx]

        try:
            values[idx] = next(iterators[idx])
        except StopIteration:
            values[idx] = None


def getnext(*args: Optional[Tuple[Any, Match]]) -> int:
    """
    Get the next item to take from a collection of matches

    :param args: The collection of matches to take from.
    """
    to_take = 0
    minstart = -1
    for i, arg in enumerate(args):
        if arg is not None and (arg[1].start() < minstart or minstart == -1):
            minstart = arg[1].start()
            to_take = i

    return to_take


class TraceParser:
    """
    Parse afl qemu trace logs
    """

    @classmethod
    def parse(cls, log: Union[Path, bytes]) -> TraceResult:
        """
        Parse a log from either a file or a string

        :param log: The log file
        """

        if isinstance(log, bytes):
            contents = log
        elif isinstance(log, Path):
            contents = log.read_bytes()
        else:
            raise TypeError(f"log must be a string or a Path, got {type(log)}")

        res = TraceResult(array("Q"), defaultdict(set), dict())

        mapping_data = {}
        for type, regex in MAPPING_RES.items():
            mapping_data[type] = regex.search(contents)

        for typ, mtch in mapping_data.items():
            if mtch is not None:
                setattr(res, typ, int(mtch.group(typ), base=16))

        for tmatch in interleave_lambda_longest(
            getnext,
            map(lambda m: ("TRACE", m), finditer(TRACE_RE, contents)),
            map(lambda m: ("MMAP", m), finditer(MMAP_RE, contents)),
            map(lambda m: ("STRACE", m), finditer(STRACE_RE, contents)),
        ):
            typ = tmatch[0]
            mtch = tmatch[1]

            if typ == "TRACE":
                res.addrs.append(base16(mtch.group("guest_addr")))
            elif typ == "MMAP":
                for submtch in finditer(MMAP_LINE_RE, mtch.group(0)):
                    res.maps[len(res.addrs) - 1].add(
                        MMap(
                            submtch.group("start"),
                            submtch.group("end"),
                            submtch.group("size"),
                            submtch.group("prot"),
                        )
                    )
            elif typ == "STRACE":
                res.syscalls[len(res.addrs) - 1] = Syscall(
                    mtch.group("syscall_name"),
                    mtch.group("syscall_ret"),
                    mtch.group("syscall_args").split(b","),
                    mtch.groupdict().get("syscall_errno"),
                    mtch.groupdict().get("syscall_errmsg"),
                )

        return res
