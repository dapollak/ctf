#!/bin/sh
set -u -e

gcc -S -Wall -std=gnu99 -o main.S main.c -ggdb
# Here comes our amazing CFI post-processing.
# Please prepare eye bleach before continuing.
if grep 'call\s[^D]' main.S; then
  echo "ERROR: bad calls"
  exit 1
fi
sed -i 's|^\scall\s\(.*\)$|\tpush $\1\n\tcall do_call|g' main.S
sed -i 's|^\sret|jmp do_return|g' main.S
gcc -c -o main.o main.S

nasm -f elf64 cfi.asm
gcc -ggdb -Wall -std=gnu99 -o launch launch.c main.o cfi.o

gcc -o server server.c -Wall -std=gnu99 -ggdb
