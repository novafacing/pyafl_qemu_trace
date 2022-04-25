"""
Utilities for parsing afl qemu trace logs
"""

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
    r"Trace\s+(?P<trace_number>[0-9]+):\s+(?P<host_addr>0x[0-9a-fA-F]+)\s+"
    r"\[(?P<flags1>[0-9a-fA-F]+)"
    r"\/(?P<guest_addr>[0-9a-fA-F]+)"
    r"\/(?P<flags2>0x[0-9a-fA-F]+)\]"
)

MMAP_RE = compile(
    # Header ------------------------------------------------------
    r"start\s+end\s+size\s+prot\n"
    # Start-End ---------------------------------------------------
    r"(?:(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)"
    # Size Prot ---------------------------------------------------
    r"\s+(?P<size>[0-9a-fA-F]+)\s+(?P<prot>[rwx-]+)[\n]?)+"
)

MMAP_LINE_RE = compile(
    r"(?:(?P<start>[0-9a-fA-F]+)-(?P<end>[0-9a-fA-F]+)"
    # Size Prot ---------------------------------------------------
    r"\s+(?P<size>[0-9a-fA-F]+)\s+(?P<prot>[rwx-]+)[\n]?)"
)

STRACE_RE = compile(
    r"(?P<syscall_num>[0-9]+)\s+(?P<syscall_name>\w+)\((?P<syscall_args>[^\)]*)\)"
    r"(?P<syscall_output>[^=]|\n)*=\s*(?P<syscall_ret>[-]?[0-9]+)"
    r"(\s?errno\s?=\s?(?P<syscall_errno>[-]?[0-9]+)\s?\((?P<syscall_errmsg>[^\)]+)\))?"
)

V = TypeVar("V")


@define(frozen=True, slots=True)
class MMap:
    """
    Memory mapping
    """

    start: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    end: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    size: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    prot: str


@define(frozen=True, slots=True)
class Syscall:
    """
    Simple descriptor of a syscall
    """

    name: str
    ret: int = field(converter=int)
    args: List[str] = field(factory=list)
    errno: Optional[int] = field(
        default=None, converter=lambda x: int(x) if x else None
    )
    err: Optional[str] = None


@define(frozen=True, slots=True)
class TraceResult:
    """
    Result of a trace
    """

    # Straight up list of addresses
    addrs: List[int] = field(factory=list)
    # Mapping of index in addrs: list of mmaps in the mapping output at that last index before
    # the mapping
    maps: Dict[int, Set[MMap]] = field(factory=partial(defaultdict, lambda: set()))
    # Mapping of the index in addrs: syscall at that last index before the syscall
    syscalls: Dict[int, Syscall] = field(factory=dict)


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
    def parse(cls, log: Union[Path, str]) -> TraceResult:
        """
        Parse a log from either a file or a string

        :param log: The log file
        """

        if isinstance(log, str):
            contents = log
        elif isinstance(log, Path):
            contents = log.read_text(encoding="utf-8", errors="ignore")

        res = TraceResult()

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
                    mtch.group("syscall_args").split(","),
                    mtch.groupdict().get("syscall_errno"),
                    mtch.groupdict().get("syscall_errmsg"),
                )

        return res
