## _dl_runtime_resolve函数细节

当初次调用库函数，会使用_dl_runtime_resolve函数来找库函数的真实地址，并将其填充至`.got.plt`表相应的位置。

这个函数的细节简单分为：

1. 从`.rel.plt`找到相应的Elf64_Rela条目

```c
typedef struct
{
  Elf64_Addr    r_offset;       /* .got.plt中对应的地址 */
  Elf64_Xword   r_info;         /* Relocation type and symbol index */
  Elf64_Sxword  r_addend;       /* Addend */
} Elf64_Rela;
```
对应ida中
```
LOAD:00000000004004D0                 Elf64_Rela <601FF8h, 800000006h, 0> ; R_X86_64_GLOB_DAT __gmon_start__
LOAD:00000000004004E8                 Elf64_Rela <602080h, 0C00000005h, 0> ; R_X86_64_COPY stdin
LOAD:0000000000400500 ; ELF JMPREL Relocation Table
LOAD:0000000000400500                 Elf64_Rela <602018h, 100000007h, 0> ; R_X86_64_JUMP_SLOT free
LOAD:0000000000400518                 Elf64_Rela <602020h, 200000007h, 0> ; R_X86_64_JUMP_SLOT __stack_chk_fail
LOAD:0000000000400530                 Elf64_Rela <602028h, 300000007h, 0> ; R_X86_64_JUMP_SLOT memset
LOAD:0000000000400548                 Elf64_Rela <602030h, 400000007h, 0> ; R_X86_64_JUMP_SLOT alarm
LOAD:0000000000400560                 Elf64_Rela <602038h, 500000007h, 0> ; R_X86_64_JUMP_SLOT read
LOAD:0000000000400578                 Elf64_Rela <602040h, 600000007h, 0> ; R_X86_64_JUMP_SLOT __libc_start_main
```

2. 以free函数为例，symbol_index = 0x100000007 >> 32 = 1，symbol_index是free函数这个Elf32_Sym结构体在.dynsym段的索引。
```c
typedef struct
{
  Elf32_Word    st_name;   /* Symbol name (string tbl index) */
  Elf32_Addr    st_value;  /* Symbol value */
  Elf32_Word    st_size;   /* Symbol size */
  unsigned char st_info;   /* Symbol type and binding */
  unsigned char st_other;  /* Symbol visibility under glibc>=2.2 */
  Elf32_Section st_shndx;  /* Section index */
} Elf32_Sym;
```
对应的数据是
```
5F 00 00 00 12 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

3. 然后得到st_name = 0x5f, 也就是在.dynstr段的偏移

```
  0x004003f8 006c6962 632e736f 2e360065 78697400 .libc.so.6.exit.
  0x00400408 5f5f7374 61636b5f 63686b5f 6661696c __stack_chk_fail
  0x00400418 00737464 696e0063 616c6c6f 63006d65 .stdin.calloc.me
  0x00400428 6d736574 00726561 6400616c 61726d00 mset.read.alarm.
  0x00400438 61746f69 00736574 76627566 005f5f6c atoi.setvbuf.__l
  0x00400448 6962635f 73746172 745f6d61 696e0066 ibc_start_main.f
  0x00400458 72656500 5f5f676d 6f6e5f73 74617274 ree.__gmon_start
  0x00400468 5f5f0047 4c494243 5f322e34 00474c49 __.GLIBC_2.4.GLI
  0x00400478 42435f32 2e322e35 00                BC_2.2.5.
```
偏移0x5f就是字符串“free”

4. 然后就根据函数名称得到函数真实地址，填充到.got.plt，也就是Elf64_Rela.r_offset



## 漏洞利用

栈溢出的Return to dl-resolve攻击就是把上面的数据结构按照1,2,3的顺序伪造一遍。

这个题我们只需攻击第三步，把dynstr段中的“free”替换为“system”，这样就劫持了free函数触发shell。