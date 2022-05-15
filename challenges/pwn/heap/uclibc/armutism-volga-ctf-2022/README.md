# Writeup of armutism challenge from VolgaCTF 2022

TLDR: 32-bit little endian ARM challenge with uClibc libc implementation off-by-one error that leads to a four-byte overwrite on the heap.

Writeup author: [adamd](https://adamdoupe.com)

Exploit Script: [x.py](./armutism/src/build/x.py)

The challenge description given is the following:

```
Have I caught armutism??????????

nc armutism.q.2022.volgactf.ru 41337
```

The challenge also gives us a `.zip` file that has the `Dockerfile` necessary to build the challenge. 

Unfortunately, the structure of the `.zip` file doesn't correspond to the `Dockerfile`, so the first step is to change the layout to be what the `Dockerfile` expects.

## Running

In this repo I have the fixed directory structure [./armutism](./armutism) so that you can run/build the given [Dockerfile](./armutism/Dockerfile).

Build it run it locally with the following:

```bash
cd armutism
docker build . -t armutism
docker run --rm -p 1337:1337 -it armutism
```

Now you should be able to access the challenge:

```bash
nc localhost 1337
```

Rest of the write-up will contain spoilers on how to solve the challenge.

## Prep

First thing is to create a patched version of the binary so that we can run it locally using the given libc and ld:

```bash
cp ./armutism ./armutism-patched
patchelf --set-interpreter "./ld-uClibc.so.0" ./armutism-patched
patchelf --set-rpath "." ./armutism-patched
```

Next, use [pwntools](https://docs.pwntools.com/en/stable/index.html)' `checksec` to see what pwn defenses are in place.

```bash
❯ checksec ./armutism
[*] armutism
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x10000)
    RWX:      Has RWX segments
```

So this tells us that it's a ARM binary (little endian), but with no protections: stack has no canary, NX is disabled, no PIE, and has RWX segments (hopefully the stack).

Now, we need to understand what `libc` version we're dealing with.

The first hint that this isn't our normal `libc` is that the given `ld` binary is called `ld-uClibc.so.0`!

A quick google search finds that this is [µClibc (uClibc)](https://www.uclibc.org), which looks to be a libc that's a drop-in replacement for glibc for embedded systems. 

At this point we should also note that the last µClibc release was in 15 May 2012, and there's a [uClibc-ng](https://uclibc-ng.org) which is actively maintained. 
If it turns out that we need to understand this libc (which is likely, because why else would the challenge author use a non-standard libc?), then we'll need to figure out exactly which version is used.

## What is it?

The challenge seems simple enough in terms of functionality. 

The binary first leaks out a pointer (from IDA this turns out to be a stack variable).
After some experimentation, we see important properties:

1. The remote instance always returns the same value `0x40800c1c` (No ASLR).
2. Our local docker instance always returns the same value `0x40800c1c`, and this value is the same as the remote instance (If we get expoit working against local docker instance then likely it will work on remote).
3. Our local instance (Ubuntu 18.04) ran with `qemu-arm ./armutism-patched` always returns the same value `0xfffed0ac`, but this is **different** than the docker or the remote (We can dev some of the exploit on local, but we will need to verify on remote).

Then gives us a CLI menu:

```
1. Malloc
2. Exit
>>>
```

Kinda nice that this is straightforward (perhaps), and it's important to note that this is rather unlike most heap challenges, as there doesn't appear to be any `free` functionality! 
We'll need to verify while reversing.

If we ask to `malloc`, then it will ask us to `Input your size:`.

If we input something small like `2`, it will then ask us to `Input numbers:`.

Now at this point it will **accept `3` numbers**. 
When approaching the challenge, I actually didn't realize this clear off-by-one vulnerability, I only discovered that through reversing. 

## Reversing

Very simple binary, there's essentially only a `main` function. 

`main` first calls `setup`, which just does `setvbuf` to disable buffering so that the program can be used over the network (standard CTF challenge stuff here, so we can ignore it).

After a brief reversing, we have the following decompilation of the `main` function:

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int size; // [sp+0h] [bp-14h] BYREF
  int input; // [sp+4h] [bp-10h] BYREF
  int *v6; // [sp+8h] [bp-Ch]
  int i; // [sp+Ch] [bp-8h]

  setup();
  input = 0;
  printf("%p\n", &input);
  while ( 1 )
  {
    write(1, "1. Malloc\n2. Exit\n>>> ", 0x16u);
    input = 0;
    scanf("%d", &input);
    if ( input != 1 )
      break;
    size = 0;
    puts("Input your size:");
    scanf("%d", &size);
    v6 = (int *)malloc(4 * size);
    if ( size <= 99 )
    {
      puts("Input numbers:");
      for ( i = 0; i <= size; ++i )
        scanf("%d", &v6[i]);
    }
  }
  return 0;
}
```

This confirms our hunch based on interaction that there are no `free`s in the program!

Other important things to note just about functionality that will be useful for exploitation:

1. The `size` that we put in is _not_ bytes, it's number of integers (so `size*4` is what's allocated).
2. If `size` is > 100, then it will not ask for our input, but it will `malloc`! This should stand out in our mind as it's quite different than a normal heap-style CTF challenge that always asks you to fill the memory that you allocate.

## Vulnerability

And finally, I spot the bug:

```C
      for ( i = 0; i <= size; ++i )
        scanf("%d", &v6[i]);
```

This should be `i < size` not `i <= size`, which means that this allows us to write 4 bytes after an allocated heap chunk!


## Exploitation

Now, how do we turn this into an exploit to read `/tmp/flag.txt` (the location of the flag we get from the `Dockerfile`)? 
Note that it's always important to understand the goals of exploitation (even if you may not yet understand the steps to get there). 

The key question here is how does `µClibc` allocate memory and how can we use the 4 byte overwrite to control things.

We _could_ start reversing the `libc.so.0` that was given to us to understand the allocator.
But why do that if we can understand from source code?

Executing `libc.so.0` with `qemu-arm` doesn't tell us the version.
Next we try `strings ./libc.so.0 | less` and manually look for something that looks like a version number.

`NPTL 0.9.33` stands out, particularly because the latest `µClibc` version on the website is 0.9.33.2.

However, I personally like to verify this information (to avoid investing time in understand something that doesn't matter to this challenge), so I explored the [uClibc source code](https://git.uclibc.org/uClibc/tree/) to try and understand where the version goes in the binary.

The search leads us to find that this is indeed the exact version: https://git.uclibc.org/uClibc/tree/libc/unistd/confstr.c#n53

Now we can look at the actual source code!

```bash
git clone git://uclibc.org/uClibc.git
cd uClibc
git checkout v0.9.33
```

At this point I get stuck for about 45 minutes going down the wrong path!
Turns out that there's _three_ different `malloc` implementations in `uClibc` that can be chosen at compilation time.

What I personally learned from this experience is that when I think that I have source code, I should also verify that the source code corresponds to the binary!

This is ultimately how I found the discrepancy, as I found a way forward for exploitation, then saw a symbol in the binary code that wasn't present in the source code directory!
So I zoomed back out and realized that there's three libc implementations.

Turns out that the challenge uses [malloc-standard](https://git.uclibc.org/uClibc/tree/libc/stdlib/malloc-standard), which is very very close to the glibc malloc implementation (in terms of chunks), but, as it turns out, without many of the security checks!

Another very nice side-effect of using an almost glibc-compatible malloc was that [`gef`](https://gef.readthedocs.io/en/master/)'s [heap commands](https://gef.readthedocs.io/en/master/commands/heap/) would mostly work to examine the state of the heap. 

### Local Debugging

Local debugging is actually very easy since the challenge runs the binary with `qemu-arm` (which I haven't used before, but was easy to figure out through googling):

One terminal:
```bash
qemu-arm -g 1234 ./armutism-patched
```

Second terminal:
```bash
gdb-multiarch ./armutism-patched
target remote localhost:1234
```

### Heap Exploitation

After understanding the uClibc malloc-standard implementation, and particularly [the heap chunk structure](https://git.uclibc.org/uClibc/tree/libc/stdlib/malloc-standard/malloc.h#n403), we realize that the next four bytes after our chunk is the size of the next chunk:

```
    An allocated chunk looks like this:


    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if allocated            | |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                         |P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_space() bytes)                     .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk                                     |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

So the theory here is that we can overwrite the size of the next chunk, which is unallocated, to be very very big.
`glibc`'s malloc has checks to prevent this, so we'll need to see if those checks are present here.

So I started to read the [uClibc `malloc` source code](https://git.uclibc.org/uClibc/tree/libc/stdlib/malloc-standard/malloc.c#n803), and the nice thing is that since there's no frees in the program we can ignore everything related to `free`ing.

The relevant code is:

```C
    victim = av->top;
    size = chunksize(victim);

    if ((unsigned long)(size) >= (unsigned long)(nb + MINSIZE)) {
        remainder_size = size - nb;
        remainder = chunk_at_offset(victim, nb);
        av->top = remainder;
        set_head(victim, nb | PREV_INUSE);
        set_head(remainder, remainder_size | PREV_INUSE);

        check_malloced_chunk(victim, nb);
        retval = chunk2mem(victim);
        goto DONE;
    }
```

Turns out there's nothing that checks or accounts for size being so large that it overflows!

### Exploitation Plan

So a plan starts to form

1. Use vulnerability to overwrite the size of the chuck after our `malloc`ed chunk to `0xffffffff`.
2. Allocate a huge chunk, say of size `X`, which will be allocated at `&huge_chunk`. Note that we won't be able to control the content of this chunk (but that's fine, it would take a long time to send all that data), and it will still be pointing into the heap.
3. Allocate another small chunk (small enough that we can control the content). The address of this chunk will essentially be `X`+`&huge_chunk` (there's some additional size b/c of alignment and heap chunk metadata, but we'll figure that out through experimentation later).
4. Write to this small chunk. 

We should be able to create a `write-what-where` primitive!

So what to write where to get the flag?

Normally we'd start to think about ROP, overwriting `GOT` entries, overwriting `_malloc_free` hook, etc.

But, these are all complicated (and we're using a non-standard libc), so let's keep it simple.

There's no PIE and the stack is executable---let's use old-school shellcode!

Now the goal is overwrite the saved `pc` on the stack to redirect control flow to our shellcode.

So we want the third allocation to return a pointer to saved `pc` on the stack (which we know because of the stack leak), then when we provide our input we give `&saved_pc + 4` then our shellcode.
We send a `2` to trigger a return and boom, we should get the flag.


### Exploitation Stumbling Blocks

Exploitation plans hitting reality is where things get messy, and this challenge was no different.

The key to overcoming these is (always) through debugging.

So at that point I moved over to debugging on the docker container rather than the local instance (because of differences in layout, although the exploit does not rely on those).

To do that, I changed the `sh` script to include `arm-qemu` debugging options, and changed the docker container to map the debugging port.
Then I could use two terminals to: (1) run the exploit and (2) debug the challenge during exploitation.

One big stumbling block I faced is that I couldn't get the precise `&saved_pc` to be returned from the third allocation. 
I assume that this is because of alignment issues, so what I did instead was return `&saved_pc-4` then write out `0` first as part of my exploit payload.

Another big stumbling block (that was very frustrating because it happened right at the end when I properly overwrote the saved `pc`) was a segmentation fault when my shellcode was executed.

I used the following shellcode from pwntools:

```python
shellcode_src = pwn.shellcraft.arm.linux.cat("/tmp/flag.txt")
```

Luckily, through debugging I found that the exact error was a bus error, and my experience with this told me that it was due to stack misalignment. 
So I did the simplest thing possible and just incremented the stack pointer by 4 bytes first, which should fix the alignment issue:

```python
align_stack = "add sp, #4\n"
shellcode_src = pwn.shellcraft.arm.linux.cat("/tmp/flag.txt")
shellcode = pwn.asm(align_stack+shellcode_src)
```

And this worked, and I got the flag!

Also it turned out that I got first blood on this challenge (and there were no other solves during the CTF). 

[x.py](./armutism/src/build/x.py) has the full exploit script. 

Overall, this was a very fun challenge because it was in an architecture that I didn't know well (ARM), a different type of heap (uClibc), and old-school exploitation techniques.
