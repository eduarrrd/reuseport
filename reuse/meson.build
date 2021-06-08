project('bpf', 'c')

# TODO: make /usr/src/linux prefix configurable
incdir = include_directories(
    '/usr/src/linux/arch/x86/include',
    '/usr/src/linux/arch/x86/include/generated',
    '/usr/src/linux/include',
    '/usr/src/linux/arch/x86/include/uapi',
    '/usr/src/linux/arch/x86/include/generated/uapi',
    '/usr/src/linux/include/uapi',
    '/usr/src/linux/include/generated/uapi',
    '/usr/src/linux/tools/include',
    '/usr/src/linux/tools/testing/selftests/bpf',
    '/usr/src/linux/tools/lib',
)

prog_python = import('python').find_installation('python3')

# bpf_helper_defs.h used to be bundled until 5.12
bpf_helper_defs = custom_target(
    'bpf_helper_defs.h',
    output : 'bpf_helper_defs.h',
    input : '/usr/src/linux/scripts/bpf_helpers_doc.py',
    command : [prog_python, '@INPUT@', '--header'],
    capture : true
)

# Requires bpftool from ${kernel}/tools/bpf/bpftool and
# kconfig option CONFIG_DEBUG_INFO_BTF
vmlinux = custom_target(
    'vmlinux.h',
    output : 'vmlinux.h',
    input : '/sys/kernel/btf/vmlinux',
    command : ['/usr/src/linux/tools/bpf/bpftool/bpftool', 'btf', 'dump', 'file', '@INPUT@', 'format', 'c'],
    capture : true
)

libbpf_dep = dependency('libbpf')
bpf_args = [
    '-g',  # BTF instrumentation
    '-O2', # required for libbpf
    '-D__KERNEL__',
    '-D__TARGET_ARCH_x86',
    '--target=bpf',
    '-Wall', '-Wno-macro-redefined',
    '-D__BPF_TRACING__',
]

# sockex1 from samples/bpf
static_library('sockex1_kern', ['sockex1_kern.c', bpf_helper_defs], include_directories : incdir, c_args : bpf_args)
executable('sockex1_user', 'sockex1_user.c', dependencies : libbpf_dep)

# reuseport
static_library('reuseport', ['reuseport_kern.c', vmlinux], include_directories : incdir, c_args : bpf_args)
executable('reuseport', 'reuseport_user.c', dependencies : libbpf_dep)
