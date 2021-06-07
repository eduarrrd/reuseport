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
