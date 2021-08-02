# Reuseport-eBPF

## Building

Requires

* meson
* clang
* libbpf >= 0.4.0
* Kernel sources

To create a build run

```shell
$ CC=clang meson build
$ cd build/
build/$ meson compile
```

### Kernel sources

Linux sources are required. The path can be statically defined in
`meson_options.txt` or dynamically injected via a CLI option
(using the CentOS 8 prefix):

```shell
$ CC=clang meson -Dkheader_prefix="/usr/src/kernels/$(uname -r)/" build
```

## Running

```shell
build/$ sudo ./reuseport
```

Debug output:

```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Map dump:

```shell
bpftool map dump name tcp_balancing_t
```

Trace:

```shell
bpftrace -e 'kfunc:bpf_fd_reuseport_array_update_elem { printf("%p, %p\n", args->key, args->value); print(args->map_flags > BPF_EXIST); }
```

## Aside: vmlinux.h

(Note: meson does this on its own via the `vmlinux` target now.)

Generated via `bpftool dump` mechanism:

```none
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
...
```

For example:

```shell
/usr/src/linux/tools/bpf/bpftool/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
