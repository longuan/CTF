还是自己太年轻啊，看了好几遍愣是没发现漏洞，基本功慢慢都丢了。

漏洞点有两个：
- “who are u”后面的输入没有截断，printf可以泄露栈上的指针--上一个函数的rbp。
- “give me money”后面的输入存在变量覆盖，可以任意地址写。


以下内容来自：[link](http://www.cnblogs.com/L1B0/p/9090461.html#_label7_2)

先说非预期解
程序没有开任何保护，根据以上两个漏洞，就可以有如下的思路：
首先根据leak出的rbp地址定位到输入的shellcode的地址，然后再通过任意地址写改写某个函数的got为shellcode的地址即可，我的做法是覆写printf@got为shellcode的地址，exp为overwrite_got.py


预期解是使用house of spirit这种攻击方法，house of spirit的基本思想是栈上溢出的长度不够覆盖到ret，但足够覆盖某些堆指针时，可以改写该堆指针并伪造chunk，通过free将该伪造的chunk添加进bin，进而控制我们下一次malloc的地址，当然这需要通过一些检查，具体细节可以看这个[slide](https://github.com/M4xW4n9/slides/blob/master/pwn_heap/malloc-150821074656-lva1-app6891.pdf)
exp是文件house_of_spirit.py

------------

使用house-of-spirit，实质是伪造fast chunk，来控制返回地址。控制哪个返回地址也是要多试几个函数的，我本想控制check_in函数的返回地址，结果当要去free的时候，0x41那个字段已经被破坏。。上面那个大佬是控制check_in函数上层函数的返回地址。