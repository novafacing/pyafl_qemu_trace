"""
Run utilities for afl-qemu-trace
"""

from shutil import rmtree
from typing import Any, Dict, Iterator, List, Optional, Tuple
from subprocess import PIPE, CompletedProcess, TimeoutExpired, run
from tempfile import TemporaryDirectory
from os import mkfifo, unlink
from os.path import join
from contextlib import contextmanager
from multiprocessing import Process, Queue

from pyafl_qemu_trace import qemu_path, QEMUEvent


@contextmanager
def TemporaryFifo(  # pylint: disable=invalid-name
    name: str, tempdir_name: str = "/dev/shm"
) -> Iterator[str]:
    """
    Create a temporary fifo and return its path

    :param name: Name of the fifo
    :param dir: Directory to create the fifo in
    """

    tmpdir = TemporaryDirectory(dir=tempdir_name)
    filename = join(tmpdir.name, name)
    mkfifo(filename)
    try:
        yield filename
    finally:
        unlink(filename)
        rmtree(tmpdir.name)


def run_wrapper(q: Queue, args, **kwargs) -> None:
    """
    Wrapper for running subprocess.run in a multiprocess and
    passing the result to the queue

    :param q: Queue to pass the result to
    :param args: Arguments to pass to subprocess.run
    :param kwargs: Keyword arguments to pass to subprocess.run
    """
    try:
        res = run(args, **kwargs)  # pylint: disable=subprocess-run-check
        q.put(res)
    except TimeoutExpired as e:
        q.put(e)


class TraceRunner:  # pylint: disable=too-few-public-methods
    """
    Run utilities for afl-qemu-trace
    """

    @classmethod
    def run(
        cls,
        platform: str,
        binary: str,
        argv: Optional[List[str]] = None,
        envp: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        input_data: Optional[bytes] = None,
        timeout: Optional[int] = None,
        input_placeholder: Optional[str] = None,
        base_addr: Optional[int] = None,
        record_events: List[QEMUEvent] = [
            QEMUEvent.NOCHAIN,
            QEMUEvent.EXEC,
            QEMUEvent.PAGE,
            QEMUEvent.STRACE,
        ],
        ld_preloads: Optional[List[str]] = None,
        ld_library_paths: Optional[List[str]] = None,
        shm_dir: str = "/dev/shm",
    ) -> Tuple[int, bytes, bytes, bytes]:
        """
        Run a binary with afl-qemu-trace and return the raw log output
        (note: this output may be very large!)

        Note that to avoid issues, any file paths passed as arguments
        should be absolute paths.

        :param platform: A platform identifier (e.g. `x86_64`)
        :param binary: The absolute path to the binary to run
        :param argv: The arguments to pass to the binary
        :param envp: The environment variables to pass to the binary
        :param cwd: The working directory to run the binary in
        :param input_data: The input to pass to the binary. Can either be a single
            bytes object, which will be passed to stdin and the input placeholder
            file(s), *or* a dictionary of input placeholder file names to input
            data bytes objects, with `stdin` being the input data to pass to stdin,
            if any.
        :param timeout: The timeout (in seconds) to wait for the binary to exit
        :param input_placeholder: The placeholder to use for the input
            if provided, any occurrences of the placeholder in `args` will be
            replaced with a path to a file containing the contents of `stdin`.
            Multiple input_placeholders can be provided as a list, and will
            be replaced by the associated input contents provided in `input`
        :return: A tuple containing (returncode, stdout, stderr, log)
        """

        run_args: Dict[str, Any] = {}
        qemu_bin = qemu_path(platform)

        program_args = []
        program_args.append(binary)
        if argv is not None:
            program_args.extend(argv)

        if isinstance(input_data, bytes):
            run_args["input"] = input_data
        elif isinstance(input, dict) and "stdin" in input_data:
            run_args["input"] = input_data["stdin"]

        if cwd is not None:
            run_args["cwd"] = cwd

        if timeout is not None:
            run_args["timeout"] = timeout

        run_args["capture_output"] = True

        with TemporaryFifo("pipe", shm_dir) as fifo:
            args = [qemu_bin]
            args.extend(["-E", "LD_BIND_NOW=1"])

            if ld_preloads:
                args.extend(["-E", f"LD_PRELOAD={':'.join(ld_preloads)}"])

            if ld_library_paths:
                args.extend(["-E", f"LD_LIBRARY_PATH={':'.join(ld_library_paths)}"])

            if envp is not None:
                for envvar, envval in envp.items():
                    args.extend(["-E", f"{envvar}={envval}"])

            if record_events:
                args.append("-d")
                args.append(",".join(map(lambda e: str(e.value), record_events)))

                args.append("-D")
                args.append(fifo)

            if base_addr is not None:
                args.append("-B")
                args.append(f"{base_addr:#0x}")

            args.extend(program_args)

            q: Queue = Queue()

            p = Process(
                target=run_wrapper,
                args=(
                    q,
                    args,
                ),
                kwargs=run_args,
            )

            p.start()

            data = b""
            with open(fifo, "rb") as fifo_read:
                while True:
                    rv = fifo_read.read()
                    if len(rv) == 0:
                        break
                    # This is a choice -- you may want to do this differently,
                    # but if you are going to pass `data` into `TraceParser.parse`, it
                    # will want a string anyway and anything that errors isn't gonna match
                    # a regex anyway

                    data += rv
                res = q.get()

                if isinstance(res, CompletedProcess):
                    return (res.returncode, res.stdout, res.stderr, data)

                if isinstance(res, TimeoutExpired):
                    p.terminate()
                    # Try and return the data anyway even if it's incomplete
                    return (-1, b"", b"", data)
