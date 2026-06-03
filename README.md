# Embian

Embian is an Android loadable kernel module experiment for kernel-side Binder
monitoring and a hidden user-space tombstone channel.

## Current baseboard

- External-module Kbuild/Makefile layout.
- Module lifecycle split into control, netlink, and Binder monitor subsystems.
- Netlink socket creation without procfs exposure.
- Control-plane constants for a future `prctl()` + magic ABI.
- Runtime symbol resolver: one-shot kprobe discovery of `kallsyms_lookup_name`,
  immediate unregister, then `kallsyms_lookup_name`-based symbol lookup with
  per-symbol kprobe fallback.
- CFI-safe runtime calls: functions that call resolved kernel function pointers
  use `EMBIAN_NOCFI`; build flags do not globally disable CFI/KCFI.
- Hidden control path: `prctl(EMBIAN_PRCTL_OPTION, magic, command, args, 0)`
  registers or detaches a netlink client without procfs.
- Netlink protocol: fixed-size control messages support hello, ping, status,
  and detach commands, with ack/status replies.
- Binder monitor: Android vendor hooks report transaction, reply, and async
  buffer pressure events through the registered netlink client. The monitor is
  read-only and avoids Binder hot-path kprobe/kretprobe hooks.
- Binder hot path avoids sleeping locks when checking whether a client is
  registered.
- Optional client detach command; correctness must not depend on user-space
  actively unregistering before exit.

## Design constraints

- Do not expose the tombstone connection through procfs.
- Avoid making kprobe/kretprobe the default Binder interception strategy.
- Prefer a low-overhead hook path, such as Android vendor hooks or tracepoints,
  after checking target-kernel availability.

## Build

Build through the Android DDK container:

```sh
ddk build
```

The target is pinned by `.ddk-version`. The `Makefile` and `Kbuild` stay as
normal external-module files. DDK provides the containerized toolchain and
target kernel environment from the outside.

For local non-DDK experiments only, pass `KDIR` explicitly:

```sh
make KDIR=/path/to/kernel/build
```

## Smoke Test Client

Build the Android arm64 test client with the local NDK:

```sh
tools/build-embianctl.sh
```

On-device flow:

```sh
adb push embian.ko out/android-arm64/embianctl /data/local/tmp/
adb shell su -c 'insmod /data/local/tmp/embian.ko'
adb shell su -c 'chmod 755 /data/local/tmp/embianctl && /data/local/tmp/embianctl --status'
adb shell su -c '/data/local/tmp/embianctl'
```

## Acknowledgements

The monitoring scope and event taxonomy of Embian are inspired by
[Sakion-Team/Re-Kernel](https://github.com/Sakion-Team/Re-Kernel). Thanks to
the Re-Kernel authors for charting the problem space and publishing their
approach.
