#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// bpf_printk argument limits
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)
#define LOC __FILE__ ":" STRINGIFY(__LINE__) ": "

// CORE LOGIC

// TODO: Handle UDP
SEC("selector")
enum sk_action _selector(struct sk_reuseport_md *reuse) {
  struct tcphdr *tcp;

  if (reuse->ip_protocol != IPPROTO_TCP) {
    bpf_printk(LOC "IPPROTO=%d\n", reuse->ip_protocol);
    return SK_DROP;
  }

  tcp = reuse->data;
  if (tcp + 1 > reuse->data_end)
    return SK_DROP;

  bpf_printk(LOC "src: %d, dest: %d", __builtin_bswap16(tcp->source),
             __builtin_bswap16(tcp->dest));

  return SK_PASS;
}

char _license[] SEC("license") = "GPL";
