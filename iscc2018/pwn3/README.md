gg函数，Double free，没有输出无法泄露内存地址。

以上三点信息就可以确定解题思路。

利用fastbin chunk在free函数中的特点：fastbin是单链表，刚释放的fast chunk链接到链表的头部，遵循LIFO（后进先出）原则。当对一个fast chunk执行free函数，libc会检查这个chunk跟fastbin头部的fast chunk地址是否相同，如果是，产生Double free异常。否则，将该fast chunk加入fastbin头部。

利用此特点，可以得到uaf，进行fastbin attack，会得到一个地址在got表的fast chunk，将其覆盖为gg函数地址。

tips：在绕过fastbin的size检查时，不一定非得p64(0x60)，p64(0x????????00000060)也可以。
