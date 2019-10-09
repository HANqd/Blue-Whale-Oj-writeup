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
