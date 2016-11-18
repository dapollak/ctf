from pwn import *
from time import sleep
import angr

REGS_ORDER = ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def send_regs(regs):
	p = remote('trumpervisor.pwn.republican', 9000)

	for i in xrange(14):
		p.sendline(str(regs[i]))
		sleep(0.5)
		log.info('Sending {0} = {1}'.format(REGS_ORDER[i], regs[i]))		

	print p.recv(2048, timeout=1)

def find_state():
	log.info('Open angr project and load entry state')
	p = angr.Project('a.out')
	state = p.factory.entry_state(addr=0x4004ED)

	log.info('Creating and loading symbolics and constants')
	context_rcx = angr.claripy.BVS(name="context_rcx", size=8*8)
	context_rbx = angr.claripy.BVS(name="context_rbx", size=8*8)
	context_rdx = angr.claripy.BVV(int(p64(0x400).encode('hex'), 16), size=8*8)
	context_rdi = angr.claripy.BVV(int(p64(0x1aa000).encode('hex'), 16), size=8*8)
	context_rsi = angr.claripy.BVS(name="context_rsi", size=8*8)
	context_r8 = angr.claripy.BVS(name="context_r8", size=8*8)
	context_r9 = angr.claripy.BVS(name="context_r9", size=8*8)
	context_r10 = angr.claripy.BVS(name="context_r10", size=8*8)
	context_r11 = angr.claripy.BVV(int(p64(0x1).encode('hex'), 16), size=8*8)
	context_r12 = angr.claripy.BVV(int(p64(0).encode('hex'), 16), size=8*8)
	context_r13 = angr.claripy.BVS(name="context_r13", size=8*8)
	context_r14 = angr.claripy.BVS(name="context_r14", size=8*8)
	context_r15 = angr.claripy.BVV(int(p64(0).encode('hex'), 16), size=8*8)

	state.memory.store(addr=0x601088, data=context_rcx)
	state.memory.store(addr=0x6010a0, data=context_rbx)
	state.memory.store(addr=0x6010d0, data=context_rdx)
	state.memory.store(addr=0x601060, data=context_rdi)
	state.memory.store(addr=0x601090, data=context_rsi)
	state.memory.store(addr=0x601068, data=context_r8)
	state.memory.store(addr=0x6010b0, data=context_r9)
	state.memory.store(addr=0x601058, data=context_r10)
	state.memory.store(addr=0x6010c8, data=context_r11)
	state.memory.store(addr=0x601050, data=context_r12)
	state.memory.store(addr=0x6010b8, data=context_r13)
	state.memory.store(addr=0x601048, data=context_r14)
	state.memory.store(addr=0x6010c0, data=context_r15)
	
	log.info('Stepping till the end of the program')
	path = p.factory.path(state)
	path = path.step()[0].step()[0]

	for i in xrange(0x400):
		path = path.step()[0]

	path = path.step()[0].step()[0]

	log.info('Finding initial state')
	solver = path.state.se
	solver.add(path.state.memory.load(0x601039, size=1) == 0xb0)
	solver.add(path.state.memory.load(0x60103a, size=1) == 0x93)
	solver.add(path.state.memory.load(0x60103b, size=1) == 0x13)
	solver.add(path.state.memory.load(0x60103c, size=1) == 0x80)

	return [u64(c) for c in [
			p64(0)
			,solver.any_str(context_rbx)
			,solver.any_str(context_rcx)
			,solver.any_str(context_rdx)
			,solver.any_str(context_rsi)
			,solver.any_str(context_rdi)
			,solver.any_str(context_r8)
			,solver.any_str(context_r9)
			,solver.any_str(context_r10)
			,solver.any_str(context_r11)
			,solver.any_str(context_r12)
			,solver.any_str(context_r13)
			,solver.any_str(context_r14)
			,solver.any_str(context_r15)]]


def get_flag():
	p = find_state()
	send_regs(p)