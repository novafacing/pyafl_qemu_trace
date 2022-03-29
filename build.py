from pathlib import Path
from typing import List
from setuptools import setup
from subprocess import CalledProcessError, run

BINARIES_PATH = Path(__file__).with_name("binaries")

TARGETS = [
    "x86_64",
    "aarch64",
]


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


def build(_) -> None:
    """
    Build the binaries
    """
    if not _install_deps():
        raise Exception("Need either `docker-compose` or `docker compose`")
    _build_tracers()
