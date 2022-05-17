# Writeup of power challenge from VolgaCTF 2022

TLDR: Given arbitrary heap write (8-bytes), followed by a malloc and read 8-bytes: overwrite a tcache entry to change `got` of `exit`.

Writeup author: [adamd](https://adamdoupe.com)

Exploit Script: [x.py](./x.py)

The challenge description given is the following:

```
Some days ago I found some cool new thing about heap internals. Will you be able to follow up and exploit it?

nc power.q.2022.volgactf.ru 1337

```

We're given the [power](./power) binary, [libc.so.6](./libc.so.6), and [ld.so](./ld.so).

## Reversing

The binary is quite simple, which can be discovered through running it and also reversing.

The essential functionality is:

```C
ptr = malloc(0x40uLL);
malloc(0x10uLL);
free(ptr);

// Leak Heap Base

// Arbitrary heap write

// Checks to make sure you didn't mess directly with the heap chunk

    buf = malloc(0x40uLL);
    read(0, buf, 8uLL);
    exit(0);
```

Now checking the mitigations of the binary:

```bash
checksec ./power
[*] power
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Partial RELRO means that we can overwrite GOT entries (we be thinking of what we want), and no PIE means that we know where to code segment will be.

## Exploitation

So the plan for this exploitation is fairly clear: we need to change eight bytes on the heap that will cause the `malloc(0x40)` after the arbitrary write to return whatever pointer we want.

Then, the `read(0, buf, 8uLL);` will allow us to write 8 bytes there.

The very next thing that's called is `exit`, so we should plan on overwriting the GOT entry of `exit` with a one-gadget or something to pop a shell and get the flag!

One problem with this idea is that with ASLR we might not know where the one_gadget is located, but I figured once we got all that working we can tackle that problem next (or maybe use ROP on the code since there's code randomization).

Now the question that the challenge is asking of us is _what_ to overwrite.

First step is to understand what version of glibc we're working with:

```bash
$ ./libc.so.6
GNU C Library (Debian GLIBC 2.31-13+deb11u3) stable release version 2.31
...
```

That's when I started to look at only the allocation pattern:

```C
ptr = malloc(0x40)
malloc(0x10)
free(ptr)

malloc(0x40)
```


Because this is a version of glibc that support tcache, the last `malloc(0x40)` will cause glibc to first look for an entry on the tcache, and if it exists, then it will return that right away.

Luckily, there _is_ something on the tcache because of the `free` of the first `malloc(0x40)`. 
And, because we know that the sizes are the same, we know that it is returned!

I first poked around the glibc malloc code for version 2.31 (always a good thing to do) to see where the tcache structure is stored.

Turns out to actually be stored on the heap as a chunk (TIL).

At this point, rather than trying to figure it out directly, I turned to debugging.

I ran the program, debugged right after the free, and examined the heap memory until I saw the pointer that was `free`d.

This was located at offset `0xa8` from the heap base (which the binary gives to us).

Then, I put this all together with `pwntools`.

At this point, I didn't know what to jump to, but I could control the GOT entry of `exit`. 

I started thinking about ROP, then when back to the binary to see what other functions it calls.

That's when I saw a function called `win`, which will read out and print the flag.

I didn't even see it while reversing, silly me.

When I noticed it, then changing the script to jump to the `win` function rather than `exit` was fairly easy.

[x.py](./x.py) has the full exploit script. 
