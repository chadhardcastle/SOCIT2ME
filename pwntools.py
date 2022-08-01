#!/bin/python3

from hashlib import md5
from pwn import *

print (cyclic(50))
print(cyclic_find("laaa"))

print(shellcraft.sh())
print(hexdump(asm(shellcraft.sh())))

#opens terminal session
#p = process("/bin/sh")
#p.sendline("echo hello;")
#p.interactive()

#creates remote session (eg. netcat)
#r = remote("127.0.0.1", 1234)
#p.sendline("echo hello;")
#p.interactive()
#r.close()

#packing and unpacking numbers. Useful for exploits and passing data over the network
print(p32(0x13371337))
print(hex(u32(p32(0x13371337))))

l = ELF('/bin/bash')

print(hex(l.address))
print(hex(l.entry))

print(hex(l.got['write']))
print(hex(l.plt['write']))

for address in l.search(b'/bin/sh\x00'):
    print(hex(address))
    
print(hex(next(l.search(asm('jmp esp')))))

r = ROP(l)
print(r.rbx)

print(xor(xor("A","B"),"A"))
print(b64e(b"test"))
print(b64d(b"dGVzdA=="))
print(md5sumhex(b"hello"))
print(sha1sumhex(b"hello"))

print(bits(b'a'))
print(unbits([0, 1, 1, 0, 0, 0, 0, 1]))