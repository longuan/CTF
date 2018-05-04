#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vuln()
{
	char buf[64];

	gets(buf);
	printf("You said: %s\n", buf);
}

int main(int argc, char **argv)
{
	setvbuf(stdout , NULL , _IONBF , 1) ; 
	setvbuf(stdin , NULL , _IONBF , 1) ; 
	setvbuf(stderr , NULL  , _IONBF , 1) ; 
	vuln();

	return 0;
}
