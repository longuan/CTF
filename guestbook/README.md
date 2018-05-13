题目来自：jarvisoj.com

很经典的Double Free。在delete函数中，free之前没有检查这个post是否在使用，同时free之后指针没有置空。

```c
int delete()
{
  int v1; // [rsp+Ch] [rbp-4h]

  if ( *(_QWORD *)(big_chunk + 8) <= 0LL )
    return puts("No posts yet.");
  
  printf("Post number: ");
  v1 = get_number();
  
  if ( v1 < 0 || (signed __int64)v1 >= *(_QWORD *)big_chunk )
    return puts("Invalid number!");
  
  --*(_QWORD *)(big_chunk + 8);
  *(_QWORD *)(big_chunk + 24LL * v1 + 16) = 0LL;
  *(_QWORD *)(big_chunk + 24LL * v1 + 24) = 0LL;
  free(*(void **)(big_chunk + 24LL * v1 + 32));
  return puts("Done.");
}
```

----------

这里考虑下一步的攻击，常与Double Free结合的攻击有两个：fastbin attack、unlink。由于这里new函数和edit函数都有0x80对齐操作，所以fastbin attack不能用。

```c
// new函数中
if ( size > 4096 )
    size = 4096;
chunk_addr = malloc((128 - size % 128) % 128 + size);
```

```
//edit函数中
if ( v2 != *(_QWORD *)(big_chunk + 24LL * v3 + 24) )
{
    v1 = big_chunk;
    *(_QWORD *)(v1 + 24LL * v3 + 32) = realloc(*(void **)(big_chunk + 24LL * v3 + 32), (128 - v2 % 128) % 128 + v2);
    *(_QWORD *)(big_chunk + 24LL * v3 + 24) = v2;
}
```


------------------

使用unlink攻击需要有一个指向当前堆块的“全局指针”，此题中“全局指针”位于堆区。

```c
v0 = malloc(0x1810uLL);
big_chunk = (__int64)v0;
*v0 = 256LL;
result = (_QWORD *)big_chunk;
*(_QWORD *)(big_chunk + 8) = 0LL;
```

所以需要先利用realloc泄露堆地址，详细见exp.py文件

---------------

现在可以完成unlink攻击了，之后选择泄露atoi函数的地址，找到libc的基地址，然后将其修改为system函数地址。将atoi的got表地址修改为system地址的时候要注意，不要破坏程序bss段的stdout和stdin地址。