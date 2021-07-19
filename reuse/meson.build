project('bpf', 'c')

khp = get_option('kheader_prefix')
kh = include_directories(
    khp / 'arch/x86/include',
    khp / 'arch/x86/include/generated',
    khp / 'include',
    khp / 'arch/x86/include/uapi',
    khp / 'arch/x86/include/generated/uapi',
    khp / 'include/uapi',
    khp / 'include/generated/uapi',
    khp / 'tools/include',
    khp / 'tools/testing/selftests/bpf',
    khp / 'tools/lib',
)

kh_tools = include_directories(
    khp / 'tools/include',
    khp / 'tools/testing/selftests/bpf',
    khp / 'tools/lib',
)

prog_python = import('python').find_installation('python3')
prog_bpftool = find_program('bpftool', khp / 'tools/bpf/bpftool/bpftool')

# bpf_helper_defs.h used to be bundled until 5.12
bpf_helper_defs = custom_target(
    'bpf_helper_defs.h',
    output : 'bpf_helper_defs.h',
    input : khp / 'scripts/bpf_helpers_doc.py',
    command : [prog_python, '@INPUT@', '--header'],
    capture : true
)

# Requires bpftool from ${kernel}/tools/bpf/bpftool and
# kconfig option CONFIG_DEBUG_INFO_BTF
vmlinux = custom_target(
    'vmlinux.h',
    output : 'vmlinux.h',
    input : '/sys/kernel/btf/vmlinux',
    command : [prog_bpftool, 'btf', 'dump', 'file', '@INPUT@', 'format', 'c'],
    capture : true
)

libbpf_dep = dependency('libbpf', version : '>=0.4.0')
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
static_library('sockex1_kern', ['sockex1_kern.c', bpf_helper_defs], include_directories : [kh, kh_tools], c_args : bpf_args)
executable('sockex1_user', 'sockex1_user.c', dependencies : libbpf_dep, build_by_default : false)

# reuseport
static_library('reuseport', ['reuseport_kern.c', vmlinux], include_directories : kh, c_args : bpf_args)
executable('reuseport', 'reuseport_user.c', dependencies : libbpf_dep)
