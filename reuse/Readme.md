# Reuseport-eBPF

## Building

Requires

* meson
* clang
* libbpf

To create a build run

```shell
$ CC=clang meson build
$ cd build/
build/$ meson compile
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
/usr/src/linux/tools/bpf/bpftool/bpftool map dump name tcp_balancing_t
```

Trace:

```shell
bpftrace -e 'kfunc:bpf_fd_reuseport_array_update_elem { printf("%p, %p\n", args->key, args->value); print(args->map_flags > BPF_EXIST); }
```

## vmlinux.h

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
