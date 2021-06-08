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
  struct iphdr ip;

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
  bpf_printk(LOC "src: %d, dest: %d", __builtin_bswap32(ip.saddr),
             __builtin_bswap32(ip.daddr));
  
  return SK_PASS;
}

char _license[] SEC("license") = "GPL";
