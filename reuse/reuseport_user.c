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

int main(int ac, char **argv) {
  struct bpf_object *obj;
  int prog_fd;
  char filename[] = "libreuseport.a.p/reuseport_kern.c.o";
  int64_t sock;

  if (bpf_prog_load(filename, BPF_PROG_TYPE_SK_REUSEPORT, &obj, &prog_fd))
    return 1;

  sock = open_sock();
  assert(sock >= 0);
  assert(listen(sock, 3) == 0);

  if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
                 sizeof(prog_fd)) != 0) {
    perror("Could not attach BPF prog");
    return 1;
  }

  while (true) {
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
