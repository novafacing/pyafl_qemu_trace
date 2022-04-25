[![PyPI version](https://badge.fury.io/py/pyafl-qemu-trace.svg)](https://badge.fury.io/py/pyafl-qemu-trace)
# pyafl_qemu_trace

pip-installable afl-qemu-trace python package

## Installation

```
python3 -m pip install pyafl-qemu-trace
```

## Building

If you would like to build this package, clone it and run `poetry build -f wheel`.

You will need to have `poetry`, `docker`, and `docker-compose` or `docker compose` (v2)
installed.

## Examples

```python
from pyafl_qemu_trace import qemu_path

# Get the path to the tracer binary
tracer = qemu_path("x86_64")

# Run the tracer with the provided wrapper
from pyafl_qemu_trace import TraceRunner
from shutil import which

retcode, stdout, stderr, log = TraceRunner.run(
    "x86_64", 
    which("xxd"), 
    cwd="/tmp", 
    input_data="\x41" * 400, 
    timeout=10
)

# Parse the output of the tracer into a programmatically
# workable data structure result
from pyafl_qemu_trace import TraceParser

result = TraceParser.parse(log)

print(f"The trace has {len(result.addrs)} instructions!")
```

## Requirements

Either `docker-compose` or `docker compose` should be available at build time, but when
installing, no dependencies are required, this basically just downloads a bunch of
binaries for you.

## Targets

Supported targets for `afl-qemu-trace` are as follows, but at the moment only `x86_64`
and `aarch64` are built -- the infrastructure to generate the rest is already in place,
however, I just need to enable it.

```txt
aarch64-softmmu
alpha-softmmu
arm-softmmu
avr-softmmu
cris-softmmu
hppa-softmmu
i386-softmmu
m68k-softmmu
microblaze-softmmu
microblazeel-softmmu
mips-softmmu
mips64-softmmu
mips64el-softmmu
mipsel-softmmu
moxie-softmmu
nios2-softmmu
or1k-softmmu
ppc-softmmu
ppc64-softmmu
riscv32-softmmu
riscv64-softmmu
rx-softmmu
s390x-softmmu
sh4-softmmu
sh4eb-softmmu
sparc-softmmu
sparc64-softmmu
tricore-softmmu
x86_64-softmmu
xtensa-softmmu
xtensaeb-softmmu
aarch64
aarch64_be
alpha
arm
armeb
cris
hexagon
hppa
i386
m68k
microblaze
microblazeel
mips
mips64
mips64el
mipsel
mipsn32
mipsn32el
nios2
or1k
ppc
ppc64
ppc64le
riscv32
riscv64
s390x
sh4
sh4eb
sparc
sparc32plus
sparc64
x86_64
xtensa
xtensaeb
```