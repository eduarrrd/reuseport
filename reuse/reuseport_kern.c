#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef BALANCER_COUNT
#define BALANCER_COUNT 2
#endif

// bpf_printk argument limits
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define LOC __FILE__ ":" STRINGIFY(__LINE__) ": "

const u32 zero = 0; // array access index

// MAPS

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} nonce SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, BALANCER_COUNT);
} tcp_balancing_targets SEC(".maps");

// HASHING

#define __jhash_final(a, b, c)                                                 \
  {                                                                            \
    c ^= b;                                                                    \
    c -= rol32(b, 14);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 11);                                                         \
    b ^= a;                                                                    \
    b -= rol32(a, 25);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 16);                                                         \
    a ^= c;                                                                    \
    a -= rol32(c, 4);                                                          \
    b ^= a;                                                                    \
    b -= rol32(a, 14);                                                         \
    c ^= b;                                                                    \
    c -= rol32(b, 24);                                                         \
  }
#define JHASH_INITVAL 0xdeadbeef

static inline __u32 rol32(__u32 word, unsigned int shift) {
  return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

static inline u32 hash(u32 ip) {
  u32 a, b, c, initval, *n;

  // Initialize nonce if not done already
  n = bpf_map_lookup_elem(&nonce, &zero);
  if (n == 0) {
    // Cannot happen as BPF_MAP_TYPE_ARRAY always resolves
    return SK_DROP;
  }

  if (*n == 0) {
    // TODO: Handle bpf_get_prandom_u32() == 0
    *n = bpf_get_prandom_u32();
    bpf_printk(LOC "Updating nonce to %x", *n);
  }

  initval = *n;

  initval += JHASH_INITVAL + (3 << 2);
  a = ip + initval;
  b = initval;
  c = initval;

  __jhash_final(a, b, c);
  return c;
}

// CORE LOGIC

// TODO: Handle UDP
SEC("sk_reuseport/selector")
enum sk_action _selector(struct sk_reuseport_md *reuse) {
  enum sk_action action;
  struct tcphdr *tcp;
  struct iphdr ip;
  u32 key;

  if (reuse->ip_protocol != IPPROTO_TCP) {
    bpf_printk(LOC "IPPROTO=%d\n", reuse->ip_protocol);
    return SK_DROP;
  }

  tcp = reuse->data;
  if (tcp + 1 > reuse->data_end)
    return SK_DROP;

  bpf_printk(LOC "src: %d, dest: %d", __builtin_bswap16(tcp->source),
             __builtin_bswap16(tcp->dest));

  bpf_skb_load_bytes_relative(reuse, 0, &ip, sizeof(struct iphdr),
                              (u32)BPF_HDR_START_NET);
  key = hash(__builtin_bswap32(ip.saddr)) % BALANCER_COUNT;
  bpf_printk(LOC "src: %d, dest: %d, key: %d", __builtin_bswap32(ip.saddr),
             __builtin_bswap32(ip.daddr), key);

  // side-effect sets dst socket if found
  if (bpf_sk_select_reuseport(reuse, &tcp_balancing_targets, &key, 0) == 0) {
    action = SK_PASS;
    bpf_printk(LOC "=> action: pass");
  } else {
    action = SK_DROP;
    bpf_printk(LOC "=> action: drop");
  }

  return action;
}

char _license[] SEC("license") = "GPL";
