#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <unistd.h>

#include <errno.h>
#include <linux/unistd.h>
#include <stdlib.h>

#ifndef BALANCER_COUNT
#define BALANCER_COUNT 2
#endif

const char NONCE_PATH[] = "/sys/fs/bpf/nonce";
const char TCP_MAP_PATH[] = "/sys/fs/bpf/tcpmap";

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

static inline int open_sock() {
  struct sockaddr_in sa;
  int sock;

  // SOCK_NONBLOCK for syncronous output in main loop
  sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (sock < 0) {
    printf("cannot create tcp socket\n");
    return -1;
  }

  int optval = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval)) != 0) {
    perror("Failed to mark socket SO_REUSEPORT");
    return -1;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(9999); // TODO: to cmd arg
  if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
    printf("bind to %d: %s\n", sa.sin_port, strerror(errno));
    close(sock);
    return -1;
  }

  return sock;
}

int main(int argc, char **argv) {
  struct bpf_object *obj;
  int map_fd, prog_fd;
  char filename[] = "libreuseport.a.p/reuseport_kern.c.o";
  int64_t sock;
  long err = 0;

  // 0-based index into reuseport array (i.e hash bucket) as the only arg
  // range: [0, BALANCER_COUNT)
  uint32_t key = 0;
  if (argc > 1) {
    key = atoi(argv[1]);
  }

	libbpf_set_print(libbpf_print_fn);

  obj = bpf_object__open_file(filename, NULL);
  err = libbpf_get_error(obj);
  if (err) {
    perror("Failed to open BPF elf file");
    return 1;
  }

  struct bpf_map *nonce = bpf_object__find_map_by_name(obj, "nonce");
  assert(nonce);
  assert(bpf_map__set_pin_path(nonce, NONCE_PATH) == 0);

  struct bpf_map *tcpmap = bpf_object__find_map_by_name(obj, "tcp_balancing_targets");
  assert(tcpmap);
  assert(bpf_map__set_pin_path(tcpmap, TCP_MAP_PATH) == 0);

  if (bpf_object__load(obj) != 0) {
    perror("Error loading BPF object into kernel");
    return 1;
  }

  map_fd = bpf_map__fd(tcpmap);
  assert(map_fd);

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "_selector");
  if (!prog) {
    perror("Could not find BPF program in BPF object");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  assert(prog_fd);

  sock = open_sock();
  assert(sock >= 0);
  assert(listen(sock, 3) == 0);

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                 sizeof(prog_fd)) != 0) {
    perror("Could not attach BPF prog");
    return 1;
  }

  printf("sockfd: %ld\n", sock);
  if (bpf_map_update_elem(map_fd, &key, &sock, BPF_ANY) != 0) {
    perror("Could not update reuseport array");
    return 1;
  }

  uint64_t res;
  if (bpf_map_lookup_elem(map_fd, &key, &res) != 0) {
    perror("Could not find own entry in REUSEPORT Array");
  }

  while (true) {
    uint32_t val;
    for (int i = 0; i < BALANCER_COUNT; i++) {
      if (bpf_map_lookup_elem(map_fd, &i, &val) == 0) {
        printf("%i: %i, ", i, val);
      } else {
        printf("%i: X, ", i);
      }
    }
    puts("");

    struct sockaddr_in saddr;
    socklen_t len = sizeof(struct sockaddr_in);
    int s = accept(sock, &saddr, &len);
    if (s < 0) {
      perror("Did not accept()");
    } else {
      char *ip = inet_ntoa(saddr.sin_addr);
      printf("Accepted connection from %s:%d\n", ip, ntohs(saddr.sin_port));
      if (close(s) != 0)
        perror("Error closing connection");
    }

    sleep(2);
  }

  return 0;
}
