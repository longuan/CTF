
#include "windows.h"
#include "stdio.h"

#define DLL_NAME "user32.dll"

int get_opcode()
{
    BYTE *ptr;
    int position,address;
    HINSTANCE handle;
    BOOL done_flag = FALSE;
    handle = LoadLibraryA(DLL_NAME);
    if(!handle)
    {
        printf(" load dll error!");
        getchar();
        return 0;
    }
    ptr = (BYTE*)handle;
    printf("start at 0x%x\n",handle);
    for(position = 0 ; !done_flag ; position++)
    {
        __try
        {
            if(ptr[position] == 0xFF && ptr[position+1] == 0xE4)
            {
                address = (int)ptr + position;
                printf("jmp esp found at 0x%x\n",address);
            }
        }
        __except(2)
        {
            address = (int)ptr + position;
            printf("END of 0x%x\n",address);
            done_flag = TRUE;
        }
    }
    getchar();
    return 0;
}