# REdge

## info

we're given a stripped ELF binary to reverse...

at first, I didn't know what to do and what's going on... the description told that "we've done the computation" but I didn't understand what it meant...

there was some hilarious intrinsic functions which I didn't really wanna reverse...

after calling them, it used printf to print a number, I didn't understand what that number is about... I missed something until I saw the hint...

the hint noted to look for rcx and rdx are discarded after assignment...
I thought they meant about those intrinsic functions' instructions...

I was too focused on the complex intrinsic ones...

until later I got tired and suddenly found it was the third argument to printf while the format (first) argument given to it only contains "%d" and discards the third argument...

```asm

│           0x00002c83      8985d0feffff   mov dword [var_130h], eax
│           0x00002c89      488d55d0       lea rdx, [var_30h]
│           0x00002c8d      488d8540ffff.  lea rax, [var_c0h]
│           0x00002c94      4889d6         mov rsi, rdx                ; uint32_t arg2
│           0x00002c97      4889c7         mov rdi, rax                ; void *arg1
│           0x00002c9a      e89afbffff     call fcn.00002839
│           0x00002c9f      488d3d7a0400.  lea rdi, str.You_really_think_results_have_been_disappeared__Well__you_are_wrong__I_stored_the_results_somewhere_in_the_universe___You_can_recognize_it_with_a_0x__ ; 0x3120 ; "You really think results have been disappeared? Well, you are wrong, I stored the results somewhere in the universe! ** You can recognize it with a 0x ** " ; const char *s
│           0x00002ca6      e8e5e3ffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00002cab      488d55d0       lea rdx, [var_30h]
│           0x00002caf      488b12         mov rdx, qword [rdx]
│           0x00002cb2      488d4dd8       lea rcx, [var_28h]
│           0x00002cb6      488b09         mov rcx, qword [rcx]
│           0x00002cb9      4801ca         add rdx, rcx
│           0x00002cbc      8b85d0feffff   mov eax, dword [var_130h]
│           0x00002cc2      89c6           mov esi, eax
│           0x00002cc4      488d3df00400.  lea rdi, [0x000031bb]       ; "%d\n" ; const char *format
│           0x00002ccb      b800000000     mov eax, 0
│           0x00002cd0      e8ebe3ffff     call sym.imp.printf         ; int printf(const char *format)
│           0x00002cd5      8b85d0feffff   mov eax, dword [var_130h]
│           0x00002cdb      488b75f8       mov rsi, qword [canary]
│           0x00002cdf      644833342528.  xor rsi, qword fs:[0x28]
│       ┌─< 0x00002ce8      7405           je 0x2cef
│       │   0x00002cea      e8c1e3ffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x2ce8
│       └─> 0x00002cef      c9             leave
└           0x00002cf0      c3             ret
[0x000010e0]> 
```

## solution

using radare2, open it in debug mode, and just add a breakpoint at `0x00002cbc`, then read the value of `rdx`...

```asm
│           0x55cab3011c9f      488d3d7a0400.  lea rdi, str.You_really_think_results_have_been_disappeared__Well__you_are_wrong__I_stored_the_results_somewhere_in_the_universe___You_can_recognize_it_with_a_0x__ ; 0x55cab3012120 ; "You really think results have been disappeared? Well, you are wrong, I stored the results somewhere in the universe! ** You can recognize it with a 0x ** "
│           0x55cab3011ca6      e8e5e3ffff     call sym.imp.puts       ; int puts(const char *s)
│           0x55cab3011cab      488d55d0       lea rdx, [var_30h]
│           0x55cab3011caf      488b12         mov rdx, qword [rdx]
│           0x55cab3011cb2      488d4dd8       lea rcx, [var_28h]
│           0x55cab3011cb6      488b09         mov rcx, qword [rcx]
│           0x55cab3011cb9      4801ca         add rdx, rcx
│           0x55cab3011cbc      8b85d0feffff   mov eax, dword [var_130h]
│           0x55cab3011cc2      89c6           mov esi, eax
│           0x55cab3011cc4      488d3df00400.  lea rdi, [0x55cab30121bb] ; "%d\n"
│           0x55cab3011ccb      b800000000     mov eax, 0
│           0x55cab3011cd0      e8ebe3ffff     call sym.imp.printf     ; int printf(const char *format)
│           0x55cab3011cd5      8b85d0feffff   mov eax, dword [var_130h]
│           0x55cab3011cdb      488b75f8       mov rsi, qword [var_8h]
│           0x55cab3011cdf      644833342528.  xor rsi, qword fs:[0x28]
│       ┌─< 0x55cab3011ce8      7405           je 0x55cab3011cef
│       │   0x55cab3011cea      e8c1e3ffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
│       │   ; CODE XREF from main @ 0x55cab3011ce8
│       └─> 0x55cab3011cef      c9             leave
└           0x55cab3011cf0      c3             ret

[0x55cab30100e0]> db 0x55cab3011cbc
[0x55cab30100e0]> dc
[+] SIGNAL 2 errno=0 addr=0x00000000 code=128 si_pid=0 ret=0
You really think results have been disappeared? Well, you are wrong, I stored the results somewhere in the universe! ** You can recognize it with a 0x ** 
hit breakpoint at: 0x55cab3011cbc
[0x55cab3011cbc]> dr
rax = 0x0000009b
rbx = 0x55cab3011d00
rcx = 0xfeb52d20a01aa8a6
rdx = 0x247fa385e258fdcc
```
