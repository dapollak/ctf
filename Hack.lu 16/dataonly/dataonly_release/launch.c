#define _GNU_SOURCE
#include <err.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

void DO_app_main(char *webroot);

int main(int argc, char **argv) {
  if (argc != 2)
  	errx(1, "bad invocation of launch binary");
  alarm(300);
  close(3);
/*
  if (syscall(__NR_memfd_create, "safe control stack", 0) != 3)
    err(1, "memfd creation failed");
*/
  if (open("/tmp/", O_TMPFILE|O_RDWR|O_EXCL) != 3)
    err(1, "tmpfd creation failed");
  DO_app_main(argv[1]);
}
