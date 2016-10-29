section .text


; ============= control flow stuff =============
%define SYSCALL_read 0
%define SYSCALL_write 1
%define SYSCALL_lseek 8
%define SEEK_CUR 1
%define POINTER_SIZE 8
%define STACK_FD 3

fast_abort:
  ud2

; call target function, clobbering rax
global do_call
do_call:
  ;save regs
  push rdi
  push rsi
  push rdx
  push rcx ; clobbered by syscall, needed for arg4

  ;write
  mov rax, SYSCALL_write
  mov rdi, STACK_FD
  mov rsi, rsp
  add rsi, 4 * POINTER_SIZE
  mov rdx, POINTER_SIZE
  syscall
  cmp rax, POINTER_SIZE
  jne fast_abort

  ; restore regs
  pop rcx
  pop rdx
  pop rsi
  pop rdi

  ; grab args
  pop rax ; return address
  pop rax ; target address

  ; make it look like a normal stackframe
  push 0x01234567
  jmp rax


; return to caller, clobbering rdi
global do_return
do_return:
  ; remove 0x01234567
  add rsp, POINTER_SIZE

  ; save rax
  push rax

  ;lseek -8
  mov rax, SYSCALL_lseek
  mov rdi, STACK_FD
  mov rsi, -8
  mov rdx, SEEK_CUR
  syscall
  cmp rax, -10000
  ja fast_abort

  ;read saved pointer into rdi
  push 0
  mov rax, SYSCALL_read
  mov rdi, STACK_FD
  mov rsi, rsp
  mov rdx, POINTER_SIZE
  syscall

  ;lseek -8
  mov rax, SYSCALL_lseek
  mov rdi, STACK_FD
  mov rsi, -8
  mov rdx, SEEK_CUR
  syscall
  cmp rax, -10000
  ja fast_abort

  pop rdi

  ; restore rax
  pop rax

  ; return
  jmp rdi


; ============= syscalls =============

global DO_syscall
DO_syscall:
  mov rax, rdi
  mov rdi, rsi
  mov rsi, rdx
  mov rdx, rcx
  mov r10, r8
  mov r8, r9
  syscall
  jmp do_return