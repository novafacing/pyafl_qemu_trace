"""
Utilities for parsing afl qemu trace logs
"""

from array import array
from collections import defaultdict
from functools import partial
from json import dumps
from pathlib import Path
from re import Match, finditer
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
    cast,
)
from attr import asdict, define, field

from pyafl_qemu_trace.parse.regs import (
    TRACE_RE,
    MMAP_RE,
    MMAP_LINE_RE,
    STRACE_RE,
    MAPPING_RES,
)

base16 = partial(int, base=16)


@define(frozen=True, slots=True)
class MMap:  # pylint: disable=too-few-public-methods
    """
    Memory mapping
    """

    start: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    end: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    size: int = field(converter=lambda x: int(x, base=16))  # type: ignore
    prot: str


@define(frozen=True, slots=True)
class Syscall:  # pylint: disable=too-few-public-methods
    """
    Simple descriptor of a syscall
    """

    name: str
    ret: int = field(converter=int)
    args: List[str] = field(factory=list)
    errno: Optional[int] = field(
        default=None, converter=lambda x: int(x) if x else None  # type: ignore
    )
    err: Optional[str] = None


@define(slots=True)
class TraceResult:  # pylint: disable=too-few-public-methods
    """
    Result of a trace
    """

    # Straight up list of addresses
    addrs: array
    # Mapping of index in addrs: list of mmaps in the mapping output at that
    # last index before the mapping
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

    def export(self, where: Path) -> None:
        """
        Export the trace to a file as JSON
        """
        if not where.is_file():
            raise ValueError(f"{where} is not a file")

        where.write_text(
            dumps(
                {
                    "addrs": self.addrs.tolist(),
                    "maps": {k: list(map(asdict, v)) for k, v in self.maps.items()},
                    "syscalls": {k: asdict(v) for k, v in self.syscalls.items()},
                    "guest_base": self.guest_base,
                    "start_brk": self.start_brk,
                    "start_code": self.start_code,
                    "end_code": self.end_code,
                    "start_data": self.start_data,
                    "end_data": self.end_data,
                    "start_stack": self.start_stack,
                    "brk": self.brk,
                    "entry": self.entry,
                    "argv_start": self.argv_start,
                    "env_start": self.env_start,
                    "auxv_start": self.auxv_start,
                    "mmap_min": self.mmap_min,
                }
            )
        )


V = TypeVar("V")


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

        # TODO: Array should be typed according to the platform data size to conserve
        # space on 32-bit or smaller architectures
        res = TraceResult(array("Q"), defaultdict(set), {})

        mapping_data = {}
        for typ, regex in MAPPING_RES.items():
            mapping_data[typ] = regex.search(contents)

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
                            submtch.group("prot").decode("utf-8"),
                        )
                    )
            elif typ == "STRACE":
                errmsg = mtch.groupdict().get("syscall_errmsg")
                res.syscalls[len(res.addrs) - 1] = Syscall(
                    mtch.group("syscall_name").decode("utf-8"),
                    mtch.group("syscall_ret"),
                    mtch.group("syscall_args").decode("utf-8").split(","),
                    mtch.groupdict().get("syscall_errno"),
                    cast(bytes, errmsg).decode("utf-8") if errmsg else None,
                )

        return res
