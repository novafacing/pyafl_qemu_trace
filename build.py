from pathlib import Path
from typing import Any, Callable, List
from setuptools import setup
from subprocess import CalledProcessError, run
import sys, marshal, functools, subprocess
from functools import wraps
from subprocess import Popen, PIPE
from marshal import dumps, loads
from sys import executable


BINARIES_PATH = Path(__file__).with_name("pyafl_qemu_trace") / "binaries"

TARGETS = [
    "x86_64",
    "aarch64",
]


CHILD_SCRIPT = """
import marshal, sys, types;
fn, args, kwargs = marshal.loads(sys.stdin.buffer.read())
sys.stdout.buffer.write(
    marshal.dumps(
       types.FunctionType(fn, globals())(*args, **kwargs),
    )
)
"""


def sudo(fun: Callable) -> Callable:
    """
    Wrap a function in sudo to run it as root
    """

    @wraps(fun)
    def inner(*args, **kwargs) -> Any:
        """
        Wrapper function to execute function as root
        """
        proc_args = ["sudo", executable, "-c", CHILD_SCRIPT]
        proc = Popen(proc_args, stdin=PIPE, stdout=PIPE)
        send_data = dumps((fun.__code__, args, kwargs))
        recv_data = proc.communicate(send_data)[0]
        return loads(recv_data)

    return inner


def _has_compose_v2() -> bool:
    """
    Check whether the local docker has `docker compose` available
    as a plugin instead of a separate utility.
    """
    try:
        run("docker compose --help", check=True, capture_output=True, shell=True)
        return True
    except:
        return False


def _has_compose_v1() -> bool:
    """
    Check whether the local docker has `docker-compose` available
    as a plugin instead of a separate utility.
    """
    try:
        run("docker-compose --help", check=True, capture_output=True, shell=True)
        return True
    except:
        return False


def _docker_cmd() -> str:
    """
    Get the appropriate docker command
    """
    if _has_compose_v2():
        return "docker"
    elif _has_compose_v1():
        return "docker-compose"
    else:
        raise Exception("Need either `docker-compose` or `docker compose`")


def _install_deps() -> List[str]:
    """
    Get the install dependencies as a list
    """
    if _has_compose_v2():
        return ["docker"]
    elif _has_compose_v1():
        return ["docker-compose"]
    else:
        raise Exception("Need either `docker-compose` or `docker compose`")


def _build_tracers() -> None:
    """
    Build the tracers
    """
    for target in TARGETS:
        try:
            run(
                f"{_docker_cmd()} compose up afl_qemu_trace_{target} --build",
                capture_output=True,
                cwd=str(Path(__file__).with_name("docker").resolve()),
                check=True,
                shell=True,
            )
        except CalledProcessError as e:
            raise Exception(f"Failed to build {target}: {e}") from e

    @sudo
    def chmod(pth: str) -> None:
        """
        Chmod everything in the path to 755

        :param pth: The string path to the directory to chmod
        """
        from pathlib import Path  # pylint: disable=all

        for entry in Path(pth).iterdir():
            if entry.is_file():
                entry.chmod(0o755)

    chmod(str(BINARIES_PATH))


def build(_) -> None:
    """
    Build the binaries
    """
    if not _install_deps():
        raise Exception("Need either `docker-compose` or `docker compose`")
    _build_tracers()
