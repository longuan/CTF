#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char *a[2010];
int i=2000;
void m(void);
void f(void);
void e(void);
void p(void);

int main(void)
{
    char c;
    setbuf(stdout,NULL);
    while (1)
    {
        printf("What is you choose?\n");
        scanf("%c",&c);
        getchar();
        if(c == 'm')
        {
            m();
        }
        else if(c == 'f')
        {
            f();
        }
        else if(c == 'e')
        {
            e();
        }
        else if(c == 'p')
        {
            p();
        }
        else
        {
            break;
        }
    }
    printf("end\n");
}

void m(void)
{
    printf("now i malloc a heap\n");
    a[i] = (char *)malloc(0x100);
    printf("enter you code\n");
    gets(a[i]);
    i++;
    printf("OK!\n");
}

void f(void)
{
    int j;
    //printf("now i free a heap\n");
    printf("which heap do you want to free?\n");

    scanf("%d",&j);
    getchar();

    free(a[j+2000]);
    printf("Ok!\n");
}

void e(void)
{
    int j;
    printf("which heap do you want to edit?\n");
    scanf("%d",&j);
    getchar();
    gets(a[j+2000]);
    printf("Ok!\n");
}
void p(void)
{
    int j;
    printf("which heap do you wnat to show?\n");
    scanf("%d",&j);
    getchar();
    printf("%s\n",a[j+2000]);
    printf("end\n");
}