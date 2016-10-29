#include <x86_64-linux-gnu/asm/unistd_64.h>
#include <asm-generic/mman-common.h>
#include <asm-generic/fcntl.h>

#define size_t unsigned long
#define NULL ((void*)0)
#define false 0
#define true 1
#define bool int

#define STDIN_FD 0
#define STDOUT_FD 1
#define STACK_FD 3


/* syscall wrapper, accepts up to 5 arguments after the syscall number */
extern long DO_syscall(int syscall, ...);


/* ==== syscalls and important low-level stuff ==== */
void DO_fatal(char *str);

long DO_sys_read(int fd, char *buf, size_t len) {
  if (fd == STACK_FD)
    DO_fatal("error: bad fd passed to DO_sys_read\n");
  return DO_syscall(__NR_read, fd, buf, len);
}

long DO_sys_write(int fd, char *buf, size_t len) {
  if (fd == STACK_FD)
    DO_fatal("error: bad fd passed to DO_sys_write\n");
  return DO_syscall(__NR_write, fd, buf, len);
}

void *DO_mmap(size_t length) {
  // TODO add arg6 and properly zero it
  void *res = (void*)DO_syscall(__NR_mmap, NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0);
  if ((unsigned long)res > (unsigned long)-4096)
    DO_fatal("error: mmap failed\n");
  return res;
}

void DO_sys_exit_group(int status) {
  DO_syscall(__NR_exit_group, status);
}

void DO_exit(int status) {
  while (1) DO_sys_exit_group(status);
}

size_t DO_strlen(char *str) {
  size_t res = 0;
  while (*str != '\0') {
    str++;
    res++;
  }
  return res;
}

void DO_write(char *str) {
  DO_sys_write(STDOUT_FD, str, DO_strlen(str));
}

void DO_fatal(char *str) {
  DO_write(str);
  DO_exit(1);
}

void DO_memcpy(void *dst, void *src, size_t len) {
  char *dst_ = dst;
  char *src_ = src;
  while (len--)
    *(dst_++) = *(src_++);
}

bool DO_streq(char *a, char *b) {
  while (1) {
    if (*a != *b)
      return false;
    if (*a == '\0')
      return true;
    a++;
    b++;
  }
}

int DO_sys_open(char *path) {
  int res = DO_syscall(__NR_open, path, O_RDONLY);
  return res;
}

void DO_sys_close(int fd) {
  if (fd == STACK_FD)
    DO_fatal("error: tried to close STACK_FD\n");
  DO_syscall(__NR_close, fd);
}



/* ==== malloc ==== */
#define MALLOC_NR_OF_SIZES 10

void *malloc_freelist_heads[MALLOC_NR_OF_SIZES];
char *malloc_area_head;
char *malloc_next_alloc;
size_t malloc_area_size = 10 * 4096 * 4096; // 10MB of heap are enough for everyone


// allocate memory for custom implemented heap.
void DO_setup_malloc(void) {
  malloc_area_head = DO_mmap(malloc_area_size);
  malloc_next_alloc = malloc_area_head;
}


#define CHUNK_SIZE_BY_IDX(idx) (1 << (idx + 4))
size_t DO_chunk_size_by_idx(int idx) {
  if (idx < 0 || idx > MALLOC_NR_OF_SIZES - 1)
    DO_fatal("error: bad chunk size idx");
  return CHUNK_SIZE_BY_IDX(idx);
}

int DO_chunk_idx_by_len(size_t len) {
  if (len > CHUNK_SIZE_BY_IDX(MALLOC_NR_OF_SIZES-1))
    DO_fatal("error: too big for malloc\n");
  int chunk_idx = 0;
  while (CHUNK_SIZE_BY_IDX(chunk_idx) < len)
    chunk_idx++;  
  return chunk_idx;
}

void *DO_malloc(size_t len) {
  if ((long)len == -1)
    DO_fatal("error: absurdly huge memory allocation\n");
  len++;

  int idx = DO_chunk_idx_by_len(len);

  char *res = malloc_freelist_heads[idx];
  if (res == NULL) {
    len = DO_chunk_size_by_idx(idx);
    if (malloc_area_size - (malloc_next_alloc - malloc_area_head) <= len)
      DO_fatal("error: out of heap space\n");
    res = malloc_next_alloc;
    malloc_next_alloc += len;
  } else {
    malloc_freelist_heads[idx] = *(void**)res;
  }
  res[0] = idx;
  return res + 1;
}

void DO_free(void *ptr) {
  if (ptr == NULL)
    return;
  ptr = ((char*)ptr)-1;
  int idx = *(char*)ptr;

  *(void**)ptr = malloc_freelist_heads[idx];
  malloc_freelist_heads[idx] = ptr;
}

/* ==== application code ==== */
char *webroot;
char *language;

char DO_readbyte(void) {
  char c;
  long res = DO_sys_read(STDIN_FD, &c, 1);
  if (res == 0)
    DO_exit(0);
  if (res != 1)
    DO_fatal("error: read failed\n");
  return c;
}

char *DO_readline(size_t *outlen) {
  // buffer overflow !!
  size_t len = CHUNK_SIZE_BY_IDX(MALLOC_NR_OF_SIZES-1) - 1;
  char *buf = DO_malloc(len);
  char *p = buf;
  while (1) {
    *p = DO_readbyte();
    if (*p == '\n') {
      *p = '\0';
      if (outlen)
        *outlen = p - buf;
      break;
    }
    p++;
  }
  return buf;
}

void DO_send_file(char *path) {
  size_t root_len = DO_strlen(webroot);
  size_t path_len = DO_strlen(path);

  for (int i=0; i<(long)path_len - 1; i++) {
    if (path[i] == '.' && path[i+1] == '.') {
      DO_write("would be kinda lame if that worked...\n");
      return;
    }
  }

  char *full_path = DO_malloc(root_len + path_len + 1);
  DO_memcpy(full_path, webroot, root_len);
  DO_memcpy(full_path + root_len, path, path_len + 1);
  int fd = DO_sys_open(full_path);
  if (fd < 0) {
    DO_write("unable to open file\n");
  } else {
    char *tmp = DO_malloc(4095);
    while (1) {
      long res = DO_sys_read(fd, tmp, 4095);
      if (res <= 0)
        break;
      DO_sys_write(STDOUT_FD, tmp, res);
    }
    DO_free(tmp);
    DO_sys_close(fd);
  }
  DO_free(full_path);
}

void DO_set_language(void) {
  DO_free(language);
  language = NULL;
  size_t linelen;
  char *new_language = DO_readline(&linelen);
  if (*new_language) {
    // save memory
    language = DO_malloc(linelen+1);
    DO_memcpy(language, new_language, linelen + 1);
  }
  DO_free(new_language);
}

void DO_app_main(char *webroot_) {
  webroot = webroot_;
  DO_setup_malloc();

  while (1) {
    char *command = DO_readline(NULL);
    if (language != NULL && DO_streq(language, "german")) {
      if (DO_streq(command, "hole")) {
        DO_write("kommando verstanden, bitte pfad senden\n");
        char *path = DO_readline(NULL);
        DO_send_file(path);
        DO_free(path);
      } else if (DO_streq(command, "sprache")) {
        DO_set_language();
      } else if (DO_streq(command, "hilfe")) {
        DO_write("hole: hole datei - sende pfad in neuer zeile\n");
        DO_write("sprache: sprache aendern - sende name der sprache in neuer zeile\n");
        DO_write("hilfe: zeige diese hilfe\n");
        DO_write("ende: verbindung schliessen\n");
      } else if (DO_streq(command, "ende")) {
        DO_write("tschuess!\n");
        DO_exit(0);
      } else {
        DO_write("unbekanntes kommando - sende \"hilfe\" für hilfe\n");
      }
    } else { // must be english
      if (DO_streq(command, "get")) {
        DO_write("command understood, please send a path\n");
        char *path = DO_readline(NULL);
        DO_send_file(path);
        DO_free(path);
      } else if (DO_streq(command, "language")) {
        DO_set_language();
      } else if (DO_streq(command, "help")) {
        DO_write("get: receive a file - send path on a separate line\n");
        DO_write("language: set language - send name of new language on a separate line\n");
        DO_write("help: show this help\n");
        DO_write("quit: let the server terminate the connection\n");
      } else if (DO_streq(command, "quit")) {
        DO_write("bye!\n");
        DO_exit(0);
      } else {
        DO_write("bad command - try sending \"help\" for help\n");
      }
    }
    DO_free(command);
  }
}
