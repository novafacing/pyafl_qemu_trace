"""
Test running afl-qemu-trace on an x86_64 binary
"""

from shutil import which

from pyafl_qemu_trace import TraceRunner
from pyafl_qemu_trace import TraceParser


def test_run_x86_64() -> None:
    """
    Test running on an x86_64 binary
    """
    xxd = which("xxd")

    assert xxd is not None, "xxd not found"

    res = TraceRunner.run(
        "x86_64",
        xxd,
        cwd="/tmp",
        input_data=b"\x41" * 400,
        timeout=30,
    )
    assert res[0] == 0
    assert len(res[3]) == 8757774


def test_parse_x86_64() -> None:
    """
    Test running and parsing on an x86_64 binary
    """
    xxd = which("xxd")

    assert xxd is not None, "xxd not found"

    res = TraceRunner.run(
        "x86_64",
        xxd,
        cwd="/tmp",
        input_data=b"\x41" * 400,
        timeout=30,
    )
    tr = TraceParser.parse(res[3].decode("utf-8", errors="ignore"))
    assert len(tr.addrs) == 124859
