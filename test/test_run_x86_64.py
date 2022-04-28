"""
Test running afl-qemu-trace on an x86_64 binary
"""

from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from signal import SIGTERM
from typing import List
from psutil import Process, NoSuchProcess
from os import getpid

from angr import Project

from pyafl_qemu_trace import TraceRunner
from pyafl_qemu_trace import TraceParser
from pyafl_qemu_trace.parse.parse import TraceResult

TEST_BINS_DIR = Path(__file__).with_name("binaries")
TEST_INPUT_DIR = Path(__file__).with_name("inputs")


class DoneException(Exception):
    ...


def kill_children(parent_pid: int = getpid(), sig=SIGTERM) -> None:
    """
    Kill all child processes of a given process

    Only use this if you are sure lol

    :param parent_pid: The parent process to kill
    :param sig: The signal to send to the child processes
    """
    try:
        parent = Process(parent_pid)
    except NoSuchProcess:
        return
    children = parent.children(recursive=True)
    for process in children:
        process.send_signal(sig)


def test_run_x86_64() -> None:
    """
    Test running on an x86_64 binary
    """
    xxd = str(TEST_BINS_DIR / "xxd")

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
    xxd = str(TEST_BINS_DIR / "xxd")

    res = TraceRunner.run(
        "x86_64",
        xxd,
        cwd="/tmp",
        input_data=b"\x41" * 400,
        timeout=30,
    )
    tr = TraceParser.parse(res[3])
    assert len(tr.addrs) == 125381


def test_parse_real_x86_64() -> None:
    """
    Test running and parsing on a larger x86_64 binary
    """
    flight_routes = TEST_BINS_DIR / "Flight_Routes" / "Flight_Routes"
    flight_routes_input = (TEST_INPUT_DIR / "Flight_Routes_1").read_bytes()

    res = TraceRunner.run(
        "x86_64",
        str(flight_routes),
        cwd=str(flight_routes.parent),
        input_data=flight_routes_input,
        timeout=30,
        ld_library_paths=[str(TEST_BINS_DIR / "Flight_Routes")],
    )

    tr = TraceParser.parse(res[3])

    assert len(tr.addrs) == 1618145


def test_parse_multi_real_x86_64() -> None:
    """
    Test running and parsing on a larger x86_64 binary
    """
    flight_routes = TEST_BINS_DIR / "Flight_Routes" / "Flight_Routes"

    for i, infile in enumerate(list(TEST_INPUT_DIR.iterdir())[:5]):
        res = TraceRunner.run(
            "x86_64",
            str(flight_routes),
            cwd=str(flight_routes.parent),
            input_data=infile.read_bytes(),
            timeout=5,
            ld_library_paths=[str(TEST_BINS_DIR / "Flight_Routes")],
        )

        tr = TraceParser.parse(res[3])
        print(
            list(filter(lambda s: s.name in (b"mmap", b"open"), tr.syscalls.values()))
        )

        print(i, len(tr.addrs))


def test_parse_multi_parallel_real_x86_64() -> None:
    """
    Test running and parsing on a larger x86_64 binary in parallel
    """
    flight_routes = TEST_BINS_DIR / "Flight_Routes" / "Flight_Routes"
    t_executor = ThreadPoolExecutor()
    p_executor = ProcessPoolExecutor()
    results: List[TraceResult] = []

    try:
        jobs = set()
        for infile in list(TEST_INPUT_DIR.iterdir())[:50]:
            jobs.add(
                t_executor.submit(
                    TraceRunner.run,
                    "x86_64",
                    str(flight_routes),
                    cwd=str(flight_routes.parent),
                    input_data=infile.read_bytes(),
                    timeout=30,
                    ld_library_paths=[str(TEST_BINS_DIR / "Flight_Routes")],
                )
            )

        while len(jobs) > 0:
            for job in jobs.copy():
                if job.done():
                    try:
                        result = job.result()
                        jobs.remove(job)
                        if isinstance(result, tuple):
                            retcode, stdout, stderr, log = result
                            print(
                                f"Trace completed with: {retcode} and loglength {len(log)}"
                            )
                            jobs.add(p_executor.submit(TraceParser.parse, log))
                        elif isinstance(result, TraceResult):
                            results.append(result)
                    except Exception as e:
                        assert False, "Exception: {}".format(e)

                    print(f"{len(jobs)} jobs remaining")
                    if len(jobs) <= 0:
                        raise DoneException()
    except DoneException:
        t_executor.shutdown(wait=False, cancel_futures=True)
        p_executor.shutdown(wait=False, cancel_futures=True)
        kill_children()
        print("Done.")

    p = Project(str(flight_routes), auto_load_libs=False)
    addr_range = (
        p.loader.main_object.min_addr,
        p.loader.main_object.max_addr,
    )

    for res in results:
        # Check the number of addresses in the trace that are actually in the address space
        # we expect for the binary -- a failure here could make it difficult to convert the trace
        # into another representation or explore it as a graph.
        count_in = 0
        count_out = 0
        for addr in res.addrs:
            if addr_range[0] <= addr <= addr_range[1]:
                count_in += 1
            else:
                count_out += 1

        print(f"{count_in} addresses in, {count_out} addresses out of {len(res.addrs)}")

        assert count_out > 0, "No addresses in expected library ranges."
        assert count_in > 0, "No addresses in expected program ranges."


def test_run_x86_64_joblib() -> None:
    """
    Test running on an x86_64 binary under joblib
    """

    xxd = str(TEST_BINS_DIR / "xxd")

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
                    xxd,
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
