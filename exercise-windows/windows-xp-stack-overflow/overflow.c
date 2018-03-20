
#include "windows.h"
#include "string.h"
#include "stdlib.h"


char shellcode[] =  "ABCDEFGH"
                    "AAAAAAAA";


int main(int argc, char *argv[])
{

    char buf[8];
    strcpy(buf, shellcode);
    return 0;
}

