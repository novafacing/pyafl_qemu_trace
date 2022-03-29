# pyafl_qemu_trace


pip-installable afl-qemu-trace python package

## Requirements

Either `docker-compose` or `docker compose` should be available at build time.


## Targets

Supported targets for `afl-qemu-trace` are:

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
aarch64-linux-user
aarch64_be-linux-user
alpha-linux-user
arm-linux-user
armeb-linux-user
cris-linux-user
hexagon-linux-user
hppa-linux-user
i386-linux-user
m68k-linux-user
microblaze-linux-user
microblazeel-linux-user
mips-linux-user
mips64-linux-user
mips64el-linux-user
mipsel-linux-user
mipsn32-linux-user
mipsn32el-linux-user
nios2-linux-user
or1k-linux-user
ppc-linux-user
ppc64-linux-user
ppc64le-linux-user
riscv32-linux-user
riscv64-linux-user
s390x-linux-user
sh4-linux-user
sh4eb-linux-user
sparc-linux-user
sparc32plus-linux-user
sparc64-linux-user
x86_64-linux-user
xtensa-linux-user
xtensaeb-linux-user
```

We don't build them all by default, we just build:

```
x86_64-linux-user
```

:)

I'll update this package in the future and build all of them.