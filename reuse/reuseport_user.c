#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <errno.h>
#include <linux/unistd.h>
#include <stdlib.h>

#ifndef BALANCER_COUNT
#define BALANCER_COUNT 2
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
  return level <= LIBBPF_DEBUG ? vfprintf(stderr, format, args) : 0;
}

static inline int open_sock(int type) {
  struct sockaddr_in sa;
  int sock;

  // SOCK_NONBLOCK for syncronous output in main loop
  sock = socket(AF_INET, type | SOCK_NONBLOCK, 0);
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
  int tmap_fd, umap_fd, prog_fd;
  char filename[] = "libreuseport.a.p/reuseport_kern.c.o";
  int64_t tsock, usock;
  long err = 0;

  // 0-based index into reuseport array (i.e hash bucket) as the only arg
  // range: [0, BALANCER_COUNT)
  uint32_t key = 0;
  if (argc > 1) {
    key = atoi(argv[1]);
  }

  libbpf_set_print(libbpf_print_fn);

  struct bpf_object_open_opts opts = {.sz = sizeof(struct bpf_object_open_opts),
                                      .pin_root_path = "/sys/fs/bpf/reuseport"};
  struct bpf_object *obj = bpf_object__open_file(filename, &opts);
  err = libbpf_get_error(obj);
  if (err) {
    perror("Failed to open BPF elf file");
    return 1;
  }

  struct bpf_map *tcpmap = bpf_object__find_map_by_name(obj, "tcp_balancing_targets");
  assert(tcpmap);

  struct bpf_map *udpmap = bpf_object__find_map_by_name(obj, "udp_balancing_targets");
  assert(udpmap);

  if (bpf_object__load(obj) != 0) {
    perror("Error loading BPF object into kernel");
    return 1;
  }

  tmap_fd = bpf_map__fd(tcpmap);
  assert(tmap_fd);

  struct bpf_program *prog = bpf_object__find_program_by_name(obj, "_selector");
  if (!prog) {
    perror("Could not find BPF program in BPF object");
    return 1;
  }

  prog_fd = bpf_program__fd(prog);
  assert(prog_fd);

  // TCP
  tsock = open_sock(SOCK_STREAM);
  assert(tsock >= 0);
  assert(listen(tsock, 3) == 0);

  if (setsockopt(tsock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                 sizeof(prog_fd)) != 0) {
    perror("Could not attach BPF prog");
    return 1;
  }

  printf("TCP sockfd: %ld\n", tsock);
  if (bpf_map_update_elem(tmap_fd, &key, &tsock, BPF_ANY) != 0) {
    perror("Could not update reuseport array");
    return 1;
  }

  // UDP
  umap_fd = bpf_map__fd(udpmap);
  assert(umap_fd);

  usock = open_sock(SOCK_DGRAM);
  assert(usock >= 0);

  if (setsockopt(usock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                 sizeof(prog_fd)) != 0) {
    perror("Could not attach BPF prog");
    return 1;
  }

  printf("UDP sockfd: %ld\n", usock);
  if (bpf_map_update_elem(umap_fd, &key, &usock, BPF_ANY) != 0) {
    perror("Could not update reuseport array");
    return 1;
  }

  char timestamp[] = "2021-01-01 23:59:59";

  while (true) {
    time_t ltime = time(NULL);
    struct tm *lt = localtime(&ltime);
    strftime(timestamp, sizeof(timestamp), "%F %H:%M:%S", lt);
    printf("\n=== %s ===\n", timestamp);

    uint32_t val;
    printf("TCP map: ");
    for (int i = 0; i < BALANCER_COUNT; i++) {
      if (bpf_map_lookup_elem(tmap_fd, &i, &val) == 0) {
        printf("%i: %i, ", i, val);
      } else {
        printf("%i: X, ", i);
      }
    }
    puts("");

    printf("UDP map: ");
    for (int i = 0; i < BALANCER_COUNT; i++) {
      if (bpf_map_lookup_elem(umap_fd, &i, &val) == 0) {
        printf("%i: %i, ", i, val);
      } else {
        printf("%i: X, ", i);
      }
    }
    puts("");

    struct sockaddr_in saddr;
    socklen_t len = sizeof(struct sockaddr_in);

    int s = accept(tsock, &saddr, &len);
    if (s < 0) {
      perror("Did not accept()");
    } else {
      char *ip = inet_ntoa(saddr.sin_addr);
      printf("Accepted connection from %s:%d\n", ip, ntohs(saddr.sin_port));
      if (close(s) != 0)
        perror("Error closing connection");
    }

    ssize_t l = recvfrom(usock, NULL, 0, 0, &saddr, &len);
    if (l < 0) {
      perror("No datagrams received");
    } else {
      char *ip = inet_ntoa(saddr.sin_addr);
      printf("Accepted datagrams from %s:%d\n", ip, ntohs(saddr.sin_port));
    }

    sleep(2);
  }

  return 0;
}
