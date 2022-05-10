from collections import defaultdict
from dataclasses import dataclass, field
from math import sqrt
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type, TypeVar
from json import load

from colour import Color

from binaryninja.plugin import PluginCommand
from binaryninja.binaryview import BinaryView
from binaryninja.interaction import get_open_filename_input, get_directory_name_input
from binaryninja.highlight import HighlightColor
from binaryninja.basicblock import BasicBlock
from binaryninjaui import View, ViewType

"""
RangeMap implementation for fast lookups of ranges of values.
"""

from bisect import bisect_left
from typing import Any, Generator, Optional, Tuple, Union


class RangeMapNotFound:
    """
    A sentinel value indicating that no value was found.
    """

    ...


T = TypeVar("T")
V = TypeVar("V")


class RangeMap(Dict[T, V]):
    """Map ranges to values

    Lookups are done in O(logN) time. There are no limits set on the upper or
    lower bounds of the ranges, but ranges must not overlap.

    """

    def __init__(self, _map: Optional[Dict[T, V]] = None):
        """
        Initialize the rangemap, optionally with an existing mapping.

        :param _map: Optional mapping to initialize the rangemap with.
        """

        self._upper: List[T] = []
        self._lower: List[T] = []
        self._values: List[V] = []
        if _map is not None:
            raise NotImplementedError(
                "Initializing with an existing mapping is not supported."
            )

    def __len__(self) -> int:
        """
        Return the number of values stored in the mapping.
        """
        return len(self._values)

    def __getitem__(
        self, point_or_range: Union[Tuple[T, T], T]
    ) -> Union[V, Type[RangeMapNotFound]]:
        """
        Retrieve a value by a single point or a specific range.

        :param point_or_range: The value or value range to look up.
        """
        if isinstance(point_or_range, tuple):
            low, high = point_or_range
            i = bisect_left(self._upper, high)
            point = low
        else:
            point = point_or_range
            i = bisect_left(self._upper, point)
        if i >= len(self._values) or self._lower[i] > point:
            return RangeMapNotFound
        return self._values[i]

    def __setitem__(self, r: Tuple[T, T], value: V) -> None:
        """
        Set a value by a single point or a specific range.

        :param r: The range for this value.
        :param value: The value.
        """
        lower, upper = r
        i = bisect_left(self._upper, upper)
        if i < len(self._values) and self._lower[i] < upper:
            raise IndexError(f"No overlaps permitted: {lower}-{upper}")
        self._upper.insert(i, upper)
        self._lower.insert(i, lower)
        self._values.insert(i, value)

    def __delitem__(self, r: Tuple[T, T]) -> None:
        """
        Delete a range and its value from the mapping.
        """
        lower, upper = r
        i = bisect_left(self._upper, upper)
        if self._upper[i] != upper or self._lower[i] != lower:
            raise IndexError(f"Range not in map: {lower}-{upper}")
        del self._upper[i]
        del self._lower[i]
        del self._values[i]

    def __iter__(self) -> Generator[Tuple[T, T], None, None]:
        """
        Create an iterator over this rangemap.
        """
        yield from zip(self._lower, self._upper)

    def __contains__(self, point_or_range: Union[Tuple[T, T], V]) -> bool:
        """
        Check if a point or range is in the mapping.

        :param point_or_range: The point or range to check.
        """
        if isinstance(point_or_range, tuple):
            low, high = point_or_range
            i = bisect_left(self._upper, high)
            point = low
        else:
            point = point_or_range
            i = bisect_left(self._upper, point)
        if i >= len(self._values) or self._lower[i] > point:
            return False

        return True


@dataclass
class AngrManagementTrace:
    """
    Trace in angrmanagement format
    """

    bb_addrs: List[int]
    syscalls: List[Any]
    id: str
    created_at: str
    input_id: str
    complete: bool

    @classmethod
    def from_file(cls, file: Path) -> "AngrManagementTrace":
        """
        Load an angrmanagement trace from a file
        """
        with file.open("r") as f:
            return AngrManagementTrace(**load(f))


@dataclass
class QemuTrace:
    """
    Trace in angrmanagement format
    """

    addrs: List[int]

    def __init__(self, addrs: List[int], *args: Any, **_kwargs: Any) -> None:
        """
        Initialize the trace
        """
        self.addrs = addrs

    @classmethod
    def from_file(cls, file: Path) -> "QemuTrace":
        """
        Load an angrmanagement trace from a file
        """
        with file.open("r") as f:
            return QemuTrace(**load(f))


# This is just copied from the reface repo so we don't have to be in the env and everything
@dataclass
class TaintedCall:
    """
    A description of a call to a tainted function.
    """

    target: int  # Function being called
    source: int  # Address of call instr
    returns: int  # Where address returns to
    tainted_regs: List[str]  # List of register names that are tainted


@dataclass
class RefaceData:
    """
    Reface db
    """

    functions: Dict[str, int] = field(default_factory=dict)
    plt_entries: Dict[str, int] = field(default_factory=dict)
    stuck_points: Dict[int, List[Union[int, Dict[int, int]]]] = field(
        default_factory=dict
    )
    candidate_funcs: Dict[int, bool] = field(default_factory=dict)
    candidate_func_names: Dict[int, str] = field(default_factory=dict)
    tainted_calls: List[TaintedCall] = field(default_factory=list)
    tainted_calls_functions: Dict[int, str] = field(default_factory=dict)
    trace_inputs: List[str] = field(
        default_factory=list
    )  # List of inputs to trace w/triton

    @classmethod
    def from_file(cls, file: Path) -> "RefaceData":
        """
        Load reface data from file
        """
        with file.open("r") as f:
            return RefaceData(**load(f))


class TraceViewer:
    """
    Trace viewer plugin for Binary Ninja.
    """

    STEPS = 20

    def __init__(self) -> None:
        """
        Initialize Trace Viewer
        """
        self.traces: List[
            AngrManagementTrace
        ] = []  # List of raw traces we have imported
        self.coverage: Dict[int, int] = defaultdict(int)  # Coverage of traces
        self.colors: List[Tuple[int, HighlightColor]] = []
        self.bv = Optional[BinaryView]

        PluginCommand.register(
            "Trace Viewer: Open File (AM format)", "View execution trace(s)", self.add
        )
        PluginCommand.register(
            "Trace Viewer: Open Directory (AM format)",
            "View execution trace(s)",
            self.add_multiple,
        )
        PluginCommand.register(
            "Trace Viewer: Open File (QEMU format)",
            "View execution trace(s)",
            self.add_qemu,
        )
        PluginCommand.register(
            "Trace Viewer: Open Directory (QEMU format)",
            "View execution trace(s)",
            self.add_multiple_qemu,
        )
        PluginCommand.register(
            "Trace Viewer: Open Reface DB",
            "View reface DB overlay.",
            self.add_reface_db,
        )
        self.lookup: Optional[RangeMap] = None
        self.db: Optional[RefaceData] = None

    def check_map(self) -> None:
        """
        Check if the map is up to date.
        """
        if self.lookup is None:
            print("initializing map...")
            self.lookup = RangeMap()
            for func in self.bv.functions:
                for bbl in func.basic_blocks:
                    try:
                        self.lookup[(bbl.start, bbl.end)] = bbl
                    except Exception as e:
                        print(e)
            print("done...")

    def compute_coverage(self) -> None:
        """
        (re)-compute coverage of the traces
        """
        self.coverage.clear()

        for trace in self.traces:
            for bbl in trace.bb_addrs:
                self.coverage[bbl] += 1

    def compute_colorage(self) -> None:
        """
        (re)-compute coloring of the traces
        """
        if len(self.coverage) == 0:
            return

        mx = max(self.coverage.values())
        steps = [mx]
        while steps[-1] > 2:
            steps += [int(sqrt(steps[-1]))]

        steps += [0]

        gradient = list(Color("#deebff").range_to(Color("#b00000"), len(steps)))
        self.colors = []
        for val, color in zip(reversed(steps), gradient):
            self.colors.append(
                (
                    val,
                    HighlightColor(
                        red=int(color.red * 255),
                        green=int(color.green * 255),
                        blue=int(color.blue * 255),
                        alpha=255,
                    ),
                )
            )

    def recolor_graph(self) -> None:
        """
        Recolor the graph
        """
        for addr, val in self.coverage.items():
            for func in self.bv.get_functions_containing(addr):
                for bbl in func.basic_blocks:
                    if bbl.start <= addr <= bbl.end:
                        self.bv.set_comment_at(
                            bbl.start, f"Trace Coverage: {val} executions."
                        )
                        for i, c in enumerate(self.colors):
                            cv = c[0]
                            if val <= cv:
                                bbl.set_user_highlight(self.colors[max(0, i - 1)][1])
                                break
                        break
                break

    def add_trace(self, trace: AngrManagementTrace) -> None:
        """
        Add a trace to the trace viewer
        """
        self.traces.append(trace)

        self.compute_coverage()
        self.compute_colorage()
        self.recolor_graph()

    def add_file(self, tracefile: Path) -> None:
        """
        Add a trace file to the trace viewer
        """

        if not tracefile.exists():
            return

        if self.db is not None:
            names = list(
                map(lambda i: Path(i).with_suffix(".json").name, self.db.trace_inputs)
            )
            if tracefile.name not in names:
                return

        print(f"Loading trace file {tracefile.name}")

        trace = AngrManagementTrace.from_file(tracefile)

        self.add_trace(trace)

    def add(self, bv: BinaryView) -> None:
        """
        Add a trace to the trace viewer
        """
        self.bv = bv
        self.check_map()
        tracefile = Path(get_open_filename_input("trace file:", "*.json")).resolve()
        self.add_file(tracefile)

    def add_multiple(self, bv: BinaryView) -> None:
        """
        Add multiple traces to the trace viewer
        """
        self.bv = bv
        self.check_map()
        tracedir = Path(get_directory_name_input("trace directory:")).resolve()

        if not tracedir.is_dir():
            return

        for tracefile in tracedir.glob("*.json"):
            self.add_file(tracefile)

    def add_file_qemu(self, tracefile: Path) -> None:
        """
        Add a trace file to the trace viewer
        """
        if not tracefile.exists():
            return

        qtrace = QemuTrace.from_file(tracefile)

        bbtrace = []

        for addr in qtrace.addrs:
            # Don't add if we're in the last block (unless we are the first instr, bc then we may
            # have a self loop which we want to add)
            if not bbtrace or (
                addr < bbtrace[-1].start
                or bbtrace[-1].start < addr <= bbtrace[-1].end
                or bbtrace[-1].end < addr
            ):
                try:
                    bbl = self.lookup[addr]
                    if bbl is not RangeMapNotFound:
                        bbtrace.append(bbl)
                except Exception as e:
                    print(e)

        bb_addrs = map(lambda b: b.start, bbtrace)

        amt = AngrManagementTrace(
            bb_addrs=bb_addrs,
            syscalls=[],
            id=tracefile.name,
            created_at="NOW",
            input_id=tracefile.name,
            complete=True,
        )

        self.add_trace(amt)

    def add_file_reface(self, dbfile: Path) -> None:
        """
        Add a reface overlay
        """
        self.db = RefaceData.from_file(dbfile)
        print(f"Loaded db {self.db}")
        i = 0
        source_hl = HighlightColor(red=255, blue=133, green=253, alpha=125)
        target_hl = HighlightColor(red=242, blue=131, green=170, alpha=125)
        for sp_loc, sp_dat in self.db.stuck_points.items():
            bb_addr = int(
                sp_loc
            )  # address of basic block where the point occurs (angr bb)
            comparison = int(sp_dat[0])
            branches = {int(k): v for k, v in sp_dat[1].items()}
            cmp_bb = self.lookup.get(comparison)
            if cmp_bb is RangeMapNotFound:
                print("Couldn't find ", hex(comparison))
                continue
            cast(
                cmp_bb,
            )
            print("cmp_bb:", cmp_bb)
            self.bv.set_comment_at(comparison, f"STUCK POINT {i} CMP")
            cmp_bb.set_user_highlight(source_hl)
            for target_addr, target_times in branches.items():
                target_bb = self.lookup.get(target_addr)
                if target_bb is RangeMapNotFound:
                    continue
                self.bv.set_comment_at(
                    target_addr, f"STUCK POINT {i} TARGET ({target_times} TIMES)"
                )
                target_bb.set_user_highlight(target_hl)
            i += 1

    def add_qemu(self, bv: BinaryView) -> None:
        """
        Add a trace to the trace viewer
        """
        self.bv = bv
        self.check_map()
        tracefile = Path(get_open_filename_input("trace file:", "*.json")).resolve()
        self.add_file_qemu(tracefile)

    def add_multiple_qemu(self, bv: BinaryView) -> None:
        """
        Add multiple traces to the trace viewer
        """
        self.bv = bv
        self.check_map()
        tracedir = Path(get_directory_name_input("trace directory:")).resolve()

        if not tracedir.is_dir():
            return

        for tracefile in tracedir.glob("*.json"):
            print(f"Adding {tracefile}")
            self.add_file_qemu(tracefile)

    def add_reface_db(self, bv: BinaryView) -> None:
        """
        Open reface database overlay.
        """
        self.bv = bv
        self.check_map()
        reface_dbfile = Path(get_open_filename_input("reface db:", "*.json")).resolve()
        self.add_file_reface(reface_dbfile)


tv = TraceViewer()
