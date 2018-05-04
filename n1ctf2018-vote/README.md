1. 通过unsorted bin 泄露libc的地址, 并计算出malloc_hook的真实地址
2. 分配两个fast chunk, 再free这两个fast chunk
3. 利用UAF漏洞, 通过vote函数修改fast chunk的fd指针, 以此改变fastbin链
4. libc会把malloc_hook附近的区域当作fast chunk返回回来
5. 修改malloc_hook的值为one gadget的地址
6. 再次请求创建堆块得到shell

参考: https://github.com/DhavalKapil/ctf-writeups/blob/master/n1ctf-2018/vote/exploit.py
