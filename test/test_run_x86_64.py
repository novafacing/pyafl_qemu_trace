"""
Test running afl-qemu-trace on an x86_64 binary
"""

from shutil import which
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def test_run_x86_64_joblib() -> None:
    """
    Test running on an x86_64 binary under joblib
    """
    with ThreadPoolExecutor() as executor:
        futures = []
        for a in (
            b"\x41",
            b"\x42",
            b"\x43",
            b"\x44",
            b"\x45",
            b"\x46",
            b"\x47",
            b"\x48",
        ):
            futures.append(
                executor.submit(
                    TraceRunner.run,
                    "x86_64",
                    which("xxd"),
                    input_data=a * 400,
                    ld_library_paths=["/lib64", "/lib"],
                    timeout=5,
                )
            )

        for future in as_completed(futures):
            try:
                retcode, stdout, stderr, log = future.result()
                print(f"Completed with: {retcode} and loglength {len(log)}")
                assert len(log) == 8872190
            except Exception as e:
                assert False, "Exception: {}".format(e)
