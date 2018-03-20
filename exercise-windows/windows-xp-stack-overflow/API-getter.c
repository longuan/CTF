#include "windows.h"

#include "stdio.h"
int main(int argc,char* argv[])
{
        if(argc!=3)
        {
                printf("the number of arguments must be 3.\n");
                return 1;
        }

        HINSTANCE DLLAddr = LoadLibrary(argv[1]);
        DWORD APIAddr = (DWORD)GetProcAddress(DLLAddr,argv[2]);

        printf("DLL-Name:%s\nAddress:0x%x\n",argv[1],DLLAddr);
        printf("API-Name:%s\nAddress:0x%x\n",argv[2],APIAddr);

        return 0;
}