#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define LISTEN_PORT 1605
#define WEBROOT "./public/"

void enter_main(int s) {
  if (dup2(s, 0) != 0 || dup2(s, 1) != 1)
    err(1, "dup2");
  close(s);
  execl("./launch", "launch", WEBROOT, NULL);
  err(1, "execve failed");
}

int main(void) {
  signal(SIGCHLD, SIG_IGN);

  int ssock = socket(AF_INET, SOCK_STREAM, 0);
  if (ssock == -1)
    err(1, "socket");
  if (setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)))
    err(1, "setsockopt");
  struct sockaddr_in addr = {
    .sin_family = AF_INET,
    .sin_port = htons(LISTEN_PORT),
    .sin_addr = { .s_addr = htonl(INADDR_LOOPBACK) }
  };
  if (bind(ssock, (struct sockaddr *)&addr, sizeof(addr)))
    err(1, "bind");
  if (listen(ssock, 32))
    err(1, "listen");

  while (1) {
    int s = accept(ssock, NULL, NULL);
    if (s == -1) {
      perror("accept() failed; retrying in a second");
      sleep(1);
      continue;
    }
retry_fork:;
    pid_t child = fork();
    if (child == -1) {
      perror("fork() failed; retrying in a second");
      sleep(1);
      goto retry_fork;
    }
    if (child == 0) {
      close(ssock);
      enter_main(s);
    }
    close(s);
  }
}
