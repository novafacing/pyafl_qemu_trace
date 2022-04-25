from pathlib import Path
from typing import List
from pkg_resources import resource_filename

PREFIX = "afl-qemu-trace-"


def qemu_path(platform: str) -> str:
    """
    Get the path to the qemu tracer for the given platform
    """
    pth = Path(qemu_base(), f"{PREFIX}{platform}").resolve()
    print(pth)
    if not pth.is_file():
        raise ValueError(f"No qemu tracer for {platform}")
    return str(pth)


def qemu_base() -> str:
    """
    Get the base path to the afl-qemu-trace binaries
    """
    return resource_filename("pyafl_qemu_trace", "binaries")


def qemu_list() -> List[str]:
    """
    Get a list of available qemu tracers
    """
    return list(
        sorted(
            map(
                lambda p: p.name.replace(PREFIX, ""),
                filter(
                    lambda p: p.name.startswith(PREFIX),
                    Path(qemu_base()).glob("*"),
                ),
            )
        )
    )


from pyafl_qemu_trace.events import QEMUEvent
from pyafl_qemu_trace.run import TraceRunner
from pyafl_qemu_trace.parse import TraceParser
