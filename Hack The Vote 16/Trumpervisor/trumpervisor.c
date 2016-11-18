#include <stdio.h>
#include <inttypes.h>

uint64_t context_rcx;
uint64_t context_rbx;
uint64_t context_rdx;
uint64_t context_rdi;
uint64_t context_rsi;
uint64_t context_r8;
uint64_t context_r9;
uint64_t context_r10;
uint64_t context_r11;
uint64_t context_r12;
uint64_t context_r13;
uint64_t context_r14;
uint64_t context_r15;

uint64_t r8_reg;
uint64_t r9_reg;
uint64_t r10_reg;
uint64_t rax_reg;
uint64_t rcx_reg;

char globals[8] = { 0 };

void main() {
	uint64_t i;

	r9_reg = context_rcx;
	r9_reg -= context_r8;
	*((uint64_t*)globals) = r9_reg;
	rax_reg = context_r11;
	rax_reg &= r9_reg;
	r9_reg -= rax_reg;
	*((uint64_t*)globals) = r9_reg;

	rcx_reg = context_r13;
	rax_reg = r9_reg;
	rax_reg >>= (rcx_reg & 0xff);
	r9_reg -= rax_reg;
	*((uint64_t*)globals) = r9_reg;
	rax_reg = context_r12;
	rax_reg += r9_reg;
	rax_reg <<= 3;
	*((uint64_t*)globals) = rax_reg;

	r8_reg = 0;
	r8_reg = globals[0];
	globals[3] |= r8_reg & 0xff;
	globals[6] |= r8_reg & 0xff;
	rcx_reg = 0;
	rcx_reg = globals[1];
	globals[4] |= rcx_reg & 0xff;
	globals[7] |= rcx_reg & 0xff;
	rax_reg = 0;
	rax_reg = globals[2];
	globals[5] |= rax_reg && 0xff;

	rcx_reg = context_rdi;
	rcx_reg -= context_rbx;
	rcx_reg -= context_rdx;
	r10_reg = *((uint64_t*)globals);
	r10_reg += rcx_reg;
	*((uint64_t*)globals) = r10_reg;
	r10_reg -= context_rsi;
	*((uint64_t*)globals) = r10_reg;

	for (i = 0; i < context_rdx; i++) {
		rcx_reg = context_r15;
		r10_reg >>= rcx_reg & 0xff;
		*((uint64_t*)globals) = r10_reg;
		r10_reg -= context_r10;
		*((uint64_t*)globals) = r10_reg;
	}

	rcx_reg = context_r15;
	r10_reg <<= rcx_reg & 0xff;
	*((uint64_t*)globals) = r10_reg;
	r10_reg += context_r9;
	*((uint64_t*)globals) = r10_reg;
	r10_reg -= context_r8;
	*((uint64_t*)globals) = r10_reg;

	r10_reg += context_r14;
	*((uint64_t*)globals) = r10_reg;
	r10_reg -= context_rcx;
	*((uint64_t*)globals) = r10_reg;
}