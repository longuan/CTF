
1. 最开始32和64位都是用syscall做的，32位可以成功，64位syscall执行不了不知道为什么。最后把64位换成用mprotect去增加可执行权限后ret2shellcode

2. 要让32和64位程序执行后你要recv的东西一致才行，因为程序ret前puts了一下，这里要填点东西，然后\x00截断一下

3. flag拿到后还有个异或操作，就很简单了

以上来自https://mp.weixin.qq.com/s/6w9cW4k1m9SjEHyfP_maSg


佚名大佬有一个新方法执行shellcode：dl_make_stack_executable函数


-----------------------

这个题，32位程序的溢出偏移是0x110，64位溢出偏移为0x118。偏移不一样，这样可以把32位和64位shellcode写在一起。（涨姿势）