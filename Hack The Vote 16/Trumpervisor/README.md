Trumpervisor - RE 500
======
We are given a Windows 10 x64 driver which uses hardware-assisted virtualization features of x86-64 processors.
Unfortunately, the solution doesn't take advantage of all the capabilities of virtualization, but it was still fun to reverse the driver.

* The driver basically implements the concept of [Blue Pill](https://en.wikipedia.org/wiki/Blue_Pill_(software)) - i.e a hypervisor which virtualizes the whole system, and is loaded from within the system - we'll see an example for that behavior later :)
* The driver code is very similar to [SimpleVisor](https://github.com/ionescu007/SimpleVisor) by Alex Ionescu - I used it heavily for reference.

### Driver Analysis
The ```DriverEntry``` is at ```0x140007000``` and calls to a function at ```0x140001450```.
What that function does is:
* Creates a device named ```Trumpervisor``` which is visible to user mode applications - because of the symbolic link to the ```DosDevice``` namespace.
* Fills the device's dispatch routines table - all of them actually do nothing except ```IRP_MJ_DEVICE_CONTROL```, which is handled by the routine at ```0x140001390```.
* Checks for the existence of a previous hypervisor (like hyper-v). If one is identified, the driver returns with an error.
* If a hypervisor isn't identified and the processor supports VT-x, the driver sets a DPC on all of the available logical processors (using ```KeGenericCallDpc```) which loads the system as a VM on each one of them. Also, memory will be allocated for virtualization data (VMCS for each processor, etc...)

The DPC which finally launches the system as a VM is at address ```0x140001740```, which is also called from the driver's unload routine. This routine is used for both launching a VM and unloading a virtualization mode on a particular processor, depending on its arguments. The unloading part is implemented with a "magic sequence" which we will see later. The launching routine is at address ```0x140001630```:
![alt text](https://raw.githubusercontent.com/dapollak/ctf/master/Hack%20The%20Vote%2016/Trumpervisor/pic1.png)
The function gets part of a big memory buffer which was allocated before and will be filled with data which is needed for the VMCS initialization.
We can see a call to ```RtlCaptureContext```, which saves the current processor state in a ```CONTEXT``` structure. Then, ```vmcs_buffer1 + 1460``` is checked, and if it equals to 0, ```enter_root_mode_and_load_vmcs```, ```initialize_vmcs``` and ```vmlaunch``` instruction are called.
* ```enter_root_mode_and_load_vmcs``` at address ```0x1400017D0``` - enables vmx operation (```vmxon``` instruction) and loads current vmcs structure pointer.
* ```initialize_vmcs``` at address ```0x1400018E0``` - initializes the vmcs, a lot of uninteresting ```vmwrite``` instructions. We will return to this function later.

At the end of ```initialize_vmcs``` we can see what the guest RIP is going to be:

![alt text](https://raw.githubusercontent.com/dapollak/ctf/master/Hack%20The%20Vote%2016/Trumpervisor/pic2.png)

RDX is the vmcs1_buffer from the above function, and remembers the call for ```RtlCaptureContext(vmcs_buffer1+0xe0)```. That means that ```vmcs_buffer1+0xe0``` is a ```CONTEXT``` structure, and ```vmcs_buffer1+0x1d8```==```vmcs_buffer1+0xf8+0xe0``` which is ```CONTEXT.Rip```:
```
kd> dt nt!_context
   +0x000 P1Home           : Uint8B
   +0x008 P2Home           : Uint8B
   +0x010 P3Home           : Uint8B
   +0x018 P4Home           : Uint8B
   +0x020 P5Home           : Uint8B
   +0x028 P6Home           : Uint8B
   +0x030 ContextFlags     : Uint4B
   +0x034 MxCsr            : Uint4B
   +0x038 SegCs            : Uint2B
   +0x03a SegDs            : Uint2B
   +0x03c SegEs            : Uint2B
   +0x03e SegFs            : Uint2B
   +0x040 SegGs            : Uint2B
   +0x042 SegSs            : Uint2B
   +0x044 EFlags           : Uint4B
   +0x048 Dr0              : Uint8B
   +0x050 Dr1              : Uint8B
   +0x058 Dr2              : Uint8B
   +0x060 Dr3              : Uint8B
   +0x068 Dr6              : Uint8B
   +0x070 Dr7              : Uint8B
   +0x078 Rax              : Uint8B
   +0x080 Rcx              : Uint8B
   +0x088 Rdx              : Uint8B
   +0x090 Rbx              : Uint8B
   +0x098 Rsp              : Uint8B
   +0x0a0 Rbp              : Uint8B
   +0x0a8 Rsi              : Uint8B
   +0x0b0 Rdi              : Uint8B
   +0x0b8 R8               : Uint8B
   +0x0c0 R9               : Uint8B
   +0x0c8 R10              : Uint8B
   +0x0d0 R11              : Uint8B
   +0x0d8 R12              : Uint8B
   +0x0e0 R13              : Uint8B
   +0x0e8 R14              : Uint8B
   +0x0f0 R15              : Uint8B
   +0x0f8 Rip              : Uint8B
```
So, we know that the VM entry point is going to be at ```0x140001653``` which is one opcode after the call to RtlCaptureContext.
We can see that just before the vmlaunch, ```vmcs_buffer1 + 1460``` is set to 1, so when the VM will sstart, it will go to the second branch in ```launching_vm```. This is very similar to the operation of SimpleVisor I mentioned at the start.

### Ioctls
Lets see the dispatch routine for DeviceIoControl - 
![alt text](https://raw.githubusercontent.com/dapollak/ctf/master/Hack%20The%20Vote%2016/Trumpervisor/pic3.png)
We see two kinds of ioctls:
* At address ```0x140002210``` which sets RAX to 0x4141414141414141 and calls ```vmcall``` - Sadly, it has nothing to do with the solution.
* ```manipulate_globals``` at address ```0x1400012D0```.

### manipulate_globals function
![alt text](https://raw.githubusercontent.com/dapollak/ctf/master/Hack%20The%20Vote%2016/Trumpervisor/pic4.png)
Basically, what this function does is xor the bytes at address ```0x1400030C0``` with a cyclic 4 byte length key at ```byte_140004020``` and prints it to the debug stream - That looks like a CTF thing, so I guessed the bytes array at ```0x1400030C0``` is the xored-flag. Trying to force the 4 first bytes to be the string 'flag', we get that ```byte_140004020 = [0xb0, 0x93, 0x13, 0x80]```. Then we xored the next byte with 0xB0, and got '{'. Sheer luck? No, it's probably the flag.
After xoring the whole array, we get:
```flag{..........................}```. Close, but not exactly a cigar.

### The nc server
The challenge comes with ```nc trumpervisor.pwn.republican 9000```. After connecting, we are asked to provide register values. Then, we get a hexadecimal number back, and the connection is closed. The registers we need to provide values for are - rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15.
I couldn't figure out the connection between the binary and the server for a few hours, so I decided to check for more ```byte_140004020``` references in the binary.

### Back to the initialize_vmcs function
The only references which are not in ```manipulate_globals``` are in ```initialize_vmcs```. There are 15 references there (like the number of registers in the server minus 1) at different positions and blocks in the function, and it seems that the code bits which manipulate ```byte_140004020``` don't have any connection with the opcodes before and after them:
![alt text](https://raw.githubusercontent.com/dapollak/ctf/master/Hack%20The%20Vote%2016/Trumpervisor/pic5.png)
Moreover, we see references to ```rdx+0x198``` and ```rdx+0x1b0```. Remember that earlier we said that ```rdx+0xe0``` holds the processor context captured in ```launching_vm```? So,
* ```rdx+0x198```==```rdx+0xe0+0xb8``` which is ```CONTEXT.r8```
* ```rdx+0x1b0```==```rdx+0xe0+0xd0``` which is ```CONTEXT.r11```
 
For both of the above registers we are asked to supply a value for connecting to the server. Then I came up with the idea to extract all the pieces of code from ```initialize_vmcs``` which manipulate ```byte_140004020```, translate them into a C program and got:

```C
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
```

So, as I suspected, the ```byte_140004020``` array (which is the ```globals``` array in the code) is influenced only by the state of the registers rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15 when capturing the processor context. Then I decided to write a script that will find a possible state for these registers that will cause ```byte_140004020 = [0xb0, 0x93, 0x13, 0x80]``` which will cause the flag to be xored currectly.
I used the symbolic execution engine [angr](http://angr.io/) with the C code above:
```python
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
```

Few comments:
* Since RAX doesn't influence the array, I set it as 0
* The values for the non symbolic registers like rdx, rdi, r11, r12 and r15 come from debugging. They were constant between different runnings.
* The hardcoded addresses of the symbolics came from a binary compiled with the above source code.

after running ```trumpervisor.get_flag()```, we get the real flag in addition to the hexadecimal value (which turned out to be meaningless):
flag{HyP3rv1s04z_aRe_T3h_fuTuR3}
