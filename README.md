# reuseport

## Repository overview

`reuse/` contains a `SK_REUSPORT` BPF program and a userspace companion program demonstrating it usage.
It has its own `Readme.md` file.

### Supporting pieces

* `client/` contains a TCP connection initator that connects to an address and prints debug info
* `server/` contains a TCP listener that simply accepts incoming connections with SO_REUSEPORT enabled, printing debug messages
* `*.bt` are bpftrace(8) programs that print potentially useful info related to SO_REUSEPORT/TCP states

## Usage with pmacct/nfacctd

The https://github.com/eduarrrd/pmacct repo's `reuse` branch enables

1. `nfacctd` itself
2. the `bmp` plugin

to use the `SK_REUSPORT` BPF program from this repository.

This branch introduces new config options (with example values):

* "`reuseport_hashbucket_count: 2`":
  Use a total of 2 hashbuckets/balacing targets.
  This needs to match across all parallel running instances.
  Example scenario: running two instances of `nfacctd`.
* "`reuseport_hashbucket_index: 0`":
  Register this instance to be the (`reuseport_hashbucket_index` + 1)th instance out of `reuseport_hashbucket_count` instances total.
* "`reuseport_bpf_prog: reuseportprog.o`":
  Use the `./reuseportprog.o` ELF binary as the source of the `SK_REUSPORT` BPF program.

### Architecture

The following diagram shows how nfacctd and the BPF program interact.

```none
      nfacctd
     ┌────────────────────────────────┐
     │                                │
     │ reuseport_hashbucket_count: 5 ─┼────────────────────────────────────────────────────────────┐
     │ reuseport_hashbucket_index: 1  │                                                            │
     │                     │          │                  nfacctd                                   │
     └─────────────────────┼──────────┘                 ┌────────────────────────────────┐         │
                           │                            │                                │         │
                           │                            │ reuseport_hashbucket_count: 5 ─┼─────────┤
                           └────────────────┐           │ reuseport_hashbucket_index: 2  │         │
      nfacctd                               │           │                     │          │         │
     ┌────────────────────────────────┐     │           └─────────────────────┼──────────┘         │
     │                                │     │                                 │                    │
     │ reuseport_hashbucket_count: 5 ─┼─────┼─────────────────────────────────┼────────────────────┤
     │ reuseport_hashbucket_index: 0  │     │                                 │                    │
     │                     │          │     │                                 │                    │
     └─────────────────────┼──────────┘     │                                 │                    │
                           │                │                                 │                    │
                           │   ┌────────────┘                                 │                    │
                           │   │                                              │                    │
                           │   │                                              │                    │
                           │   │   ┌──────────────────────────────────────────┘                    │
      Userspace            │   │   │                                                               │
   ────────────────────────┼───┼───┼───────────────────────────────────────────────────────────────┼──
      Kernel               │   │   │                                                               │
                           │   │   │                                                               │
                           │   │   │                                                               │
                         ┌─▼─┬─▼─┬─▼─┬───┬───┬───┬────────┬────────────────────────┐             ┌─▼─┐
 BPF map                 │   │   │   │   │   │   │ ...    │                        │     BPF map │ 5 │
 "udp_balancing_targets" └───┴───┴───┴───┴───┴───┴────────┴────────────────────────┘     "size"  └─┬─┘
                           0   1   2   3   4   5            MAX_BALANCER_COUNT - 1                 │
                           ▲   ▲   ▲   ▲   ▲   X                                                   │
                           │   │   │   │   │   X                                                   │
                           └───┴─┬─┴───┴───┘XXXX                                                   │
                                 │                                                                 │
                         ┌───────┼────────────────────────────────────────────┐                    │
                         │       │                                            │                    │
                         │   ┌───┴────┐             balancer_count := size[0] │                    │
                         │   │ x %  y ◄────────────────────────────◄──────────┼────────────────────┘
                         │   └─▲──────┘                                       │
           BPF program   │     │            ┌─────────────────────────────────┼─────────┐
           "_selector()" │     │            │                                 │         │
                         │   ┌─┴────────────▼────┐                            │    ┌────┴─────┐
                         │   │ hash(input, seed) │                            │    │ 0x123FED │ BPF map
                         │   └────────▲──────────┘                            │    └──────────┘ "nonce"
                         │            │                                       │
                         └────────────┼───────────────────────────────────────┘
Host                                  │
──────────────────────────────────────┼─────────────────────────────────────────────────────────────────────
Network                               │
                                      │
                198.51.100.1:65533 ───┼─── 198.51.100.123:65533
                                      │
               203.0.113.111:65533 ───┴─── 203.0.113.222:65533
```

### Usage

To actually run this version of pmacct simply

1. (build the BPF program from `reuse/`)
2. build pmacct from source (consider using `nfacctd -V` as a source for `./configure` flags).
   The added functionality is NOT optional on this branch so a successful build is sufficient.
   The one additional requirement is `libbpf` (github.com/libbpf/libbpf) >= 0.4.0.
3. set the new options to your desired values in your nfacctd config file.
4. fork this config file once for each `nfacctd` instance, changing `reuseport_hashbucket_index` each time.
5. in your execution environment, be sure to raise the `RLIMIT_MEMLOCK` resource limit (BPF programs/maps are memlocked).
   For testing `ulimit -l unlimited` is sufficient.
6. launch `nfacctd` with either `CAP_BPF`, `CAP_SYS_ADMIN`, or as uid=0.

In pseudo-script form, it could look like this:

```bash
set -e -o pipefail

cd pmacctd

./autogen.sh
./configure $(nfacctd -V | tail -n+4 | head -n1)
make -j$(nproc)

cp /etc/pmacct/nfacctd-bmp01.conf nfacctd-bmp01-hash0.conf
cat >> nfacctd-bmp01-hash0.conf <<<EOF
reuseport_hashbucket_index: 0
reuseport_hashbucket_count: 2
reuseport_bpf_prog: reuseportprog.o
EOF

cp ${path_to_reuseport_repo}/reuse/build/reuseport.o reuseportprog.o
sudo bash -c 'ulimit -l unlimited; src/nfacctd -f nfacctd-bmp01-hash0.conf'
```
