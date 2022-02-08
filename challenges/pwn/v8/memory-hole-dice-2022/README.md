---
title: '[DiceCTF 2022] - memory hole'
date: 2022-02-06 15:11:55
tags:
- CTF
- PWN
- browser
- v8
---

# Summary
Escape from V8 Virtual Memory Cage with `imported_mutable_global`.

# Introduction
During this weekend, I casually played DiceCTF 2022 with my team Shellphish. And I solved two challenges: `baby-rop` and `memory hole` during the game.

It was the first time in a while that I played CTFs with OOO people: @Zardus and @adamd (internally, we call them OOOld people :) ). Initially, I didn't plan to play the CTF because of my research work. But @adamd "bullied" me into it by saying "now get me the flag" when I casually posted some techniques that could help the team solve `baby-rop`. So, I solved it.

After solving `baby-rop`, I thought I was done with the CTF. But the next day, @adamd (yes, it was always him.) posted some info about `memory hole` in our discord channel, I got immediately hooked up by the challenge: what's more exicting than bypassing the latest defence in V8? Besides, I haven't done any V8 challenge in a few months, it's a good time to pick it up again. So, I decided to have a look at it and finally solved it with a different approach from intended solution.

<!-- more -->

# Disclaimer
I'm not an expert in V8, the terminologies used in this blog post may be wrong. Please feel free to correct me if you discover anything wrong.

# Challenge
The challenge patches the original V8 source code and modifies its behaviors in the following ways: (the patch can be found [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/dice22_memory_hole/patch.patch))
1. enable a "v8 sandbox" feature
2. introduce a `setLength` function to `Array` objects.
3. introduce a typer bug in `OperationTyper::NumberClz32`
4. make some misc changes to avoid unintended solutions

In fact, the patch itself is messed up. The actual implementation of `setLength` is missing and the typer bug was unintentional and does not help much during the exploitation.

Anyways, the only relevant modifications are "v8 sandbox" and the `setLength` function. Although there is no source code, with a little bit of experiments with `%DebugPrint`, it can be easily concluded that `setLength` simply allows users to arbitrarily change the `length` field of an `Array` object, which obviously can lead to relative OOB R/W on JS heap.

Now the challenge is pretty clear: the goal is to use the relative OOB R/W to bypass the "v8 sandbox" and get code execution.

But before we actually start exploitation, we need to understand what is this "v8 sandbox".

# V8 Virtual Memory Cage
V8 started using a protection feature called "Pointer Compression" a few years back. The idea is pretty simple: represent all `JSObject` pointers like: `js_base + offset` and only store `offset`-s in memory. The `js_base` is stored in a register (let's say `$r14` here). Whenever V8 wants to dereference a `JSObject`, it will load memory from `$r14+offset`. Notice that `offset` is 32bit instead of 64bit (hence "compression"). So, `js_base+offset` is confined to a small region: attackers cannot access arbitrary address even if they can arbitrary overwrite any `offset` value.

The bypass to "Pointer Compression" is pretty simple: `ArrayBuffer` has a pointer called `backingstore`, which points whatever the content is in the `ArrayBuffer`. More importantly, the pointer it not compressed, it is stored and used as a 64bit pointer, which means overwriting this pointer and access it from `ArrayBuffer` can grant attackers arbitrary read/write capability on the whole *64-bit* address space. In recent years, almost all attackers use this technique for V8 exploitation.

Recently, @saelo added a protection against this technique by extending "Pointer Compression" and he called the protection "V8 Virtual Memory Cage", which is what "v8 sandbox" in the patch refers to. The official documentation can be found [here](https://docs.google.com/document/d/17IW7LKiHrG3ZrtbS-EI8dJHD8-b6vpqCXnP3g315K2w/edit). The idea of this protection is to get rid of the raw 64bit `backingstore` pointer in `ArrayBuffer` so that attackers cannot abuse this pointer for arbitrary read/write in the whole 64bit address space anymore.

The implementation is a little bit complicated and I'll only cover the relevant parts for the exploitation here. Interested readers can refer to the official documentation for further reading. Basically, the `backingstore` pointer is now replaced by `data_ptr`, which is dynamically calculated based on two 32bit integers on JS heap: `base_pointer` and `external_pointer`. I didn't read the source code, but I figured out the formulae by playing with `gdb` and `%DebugPrint`: `data_ptr = js_base + (external_pointer << 8) + base_pointer`. (Note that `%DebugPrint` shows the full pointer by adding the `js_base` to it). So, no matter what values `external_pointer` and `base_pointer` are, `data_ptr` is confined to a 40bit address space, we cannot use it to achieve arbitrary read/write in the 64bit address space anymore.

Let's have a look at an example:
~~~
DebugPrint: 0x17c808084329: [JSTypedArray]
 - map: 0x17c808203199 <Map(UINT32ELEMENTS)> [FastProperties]
 - prototype: 0x17c8081c94f5 <Object map = 0x17c8082031c1>
 - elements: 0x17c8080033a1 <ByteArray[0]> [UINT32ELEMENTS]
 - embedder fields: 2
 - buffer: 0x17c808084271 <ArrayBuffer map = 0x17c808203289>
 - byte_offset: 0
 - byte_length: 256
 - length: 64
 - data_ptr: 0x17c901001000
   - base_pointer: (nil)
   - external_pointer: 0x17c901001000
 - properties: 0x17c808002249 <FixedArray[0]>
 - All own properties (excluding elements): {}
 - elements: 0x17c8080033a1 <ByteArray[0]> {
        0-63: 0
 }
~~~
Here is the `%DebugPrint` output of a `Uint32Array`, the `js_base` is `0x17c800000000` here.
~~~
0x17c808084328:	0x0800224908203199	0x08084271080033a1
0x17c808084338:	0x0000000000000000	0x0000000000000100
0x17c808084348:	0x00000040080023d0	0x0000000000000000
0x17c808084358:	0x0000000001010010	0x0000000000000000 <- look at this line
~~~
In memory, there is a `0x01010010` integer, which is how `external_pointer` stored in memory. `data_ptr` is calculated by `0x17c800000000+ (0x01010010<<8) + 0 = 0x17c901001000`, which is correct according to the debug print result.

# Relative OOB R/W
After understanding the Cage, let's have a look at the challenge itself.
The challenge allows us to arbitrarily overwrite the `length` of an `Array`, which is good, but not good enough. Usually, we want to have OOB on a `TypedArray` because it can provide clean data control.

Initially, I tried `var arr = new Array(10);`, which creates a `JSArray`. While overwriting the `length` of a `JSArray` is an OK-ish primitive, it is complicated to exploit because `JSArray` will treat any value ends with `1` as a pointer, which complicates things too much. Instead, I created a `DoubleArray` by `var arr = [1.1, 2.2, 3.3];`. In this way, the values in the overflowed region will be accessible as `float` values.

As a summary, to get relative OOB R/W, we only need to use the following snippet:
~~~
var arr = [1.1, 2.2, 3.3];
arr.setLength(100);
~~~

# Arbitrary R/W Inside the Cage
After understanding how the new `ArrayBuffer` works, this part is also simple.
First, we need to create a `TypedArray` object (I used `Uint32Array`) next to the `DoubleArray`.
Next, we overwrite the `length` of the `Uint32Array` to a huge value so we can have OOB access.
Finally, we clear out both `external_pointer` and `base_pointer` of the `Uint32Array` so that its `data_ptr` becomes `js_base`.

The above procedure grants our `Uint32Array` full access to the cage because its `data_ptr` starts at `js_base` and the `length` is huge. At this point, what we need to do first is to leak the `js_base` value. Conveniently, there is one at the start of the `js_base`. We can also leak other sensitive information such as code base etc using the OOB, but they are not important in this exploitation.

So, at this stage, we have full read/write access inside the cage and `js_base` is known to us.

# Escape the Cage
Escape from the cage is not easy. Initially, I thought the only way was to find another raw 64bit pointer on JS heap and hijack it just like what we did with `backingstore`. But later, in a tweet thread (which I cannot find now), Chris Evans suggested that corrupting some values on JS heap can potentially break some assumptions of the JIT engine and lead to full address space access, which is a reasonable approach and may actually work. After some thinking, I concluded that overwriting the rwx pointer in WebAssembly also worth a try.

To sum up, after a little bit of searching and thinking, I came up with three possible approaches:
1. corrupt JS heap to break JIT function's assumptions
2. overwrite the JIT code pointer in WebAssembly
3. find a new raw 64bit pointer on JS heap and hijack it

## Attempt 1
I almost gave up the first idea immediately because analyzing the JIT compiler's assumptions sounds a lot of work and may not be feasible during a CTF.

## Attempt 2
Then I started analyzing the second idea. In Javascript, one can run webassembly code. In V8's implementation, it JIT-compiles the webassembly code and stores the code in a rwx region. So, overwriting the JIT code or the code pointer will grant us shellcode execution capability. This feature has been exploited for a few years. An detailed walkthrough on how it works can be found [here](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/). Basically, a JIT-ed Webassembly function can be created by using the following snippet:
~~~
var wasm_code2 = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod2 = new WebAssembly.Module(wasm_code2);
var wasm_instance2 = new WebAssembly.Instance(wasm_mod2);
var f = wasm_instance2.exports.main;
~~~
Overwriting the rwx region and invoke `f()` will execute the written shellcode.

In our case, the rwx region itself is outside the cage, so we cannot overwrite it directly. However, the pointer itself is still inside the cage. A `WASMInstance` looks like this in memory:
~~~
0x238b081d4324:	0x0800224908206439	0x0800224908002249
0x238b081d4334:	0x0000000008002249	0x0000238c81010000
0x238b081d4344:	0x0000000000010000	0x000055dff37429e0
0x238b081d4354:	0x000055dff38bbcd0	0x0000000000000000
0x238b081d4364:	0x0000000000000000	0x0000000000000000
0x238b081d4374:	0x000055dff38bbcf0	0x000055dff37429c0
0x238b081d4384:	0x00002dc419c9e000	0x000055dff374ede8
0x238b081d4394:	0x000055dff374ede0	0x000055dff374ee00
0x238b081d43a4:	0x000055dff374edf8	0x000055dff37429d0
0x238b081d43b4:	0x000055dff38bbd10	0x000055dff38bbd30
0x238b081d43c4:	0x000055dff38bbd50	0x000055dff3764f29
0x238b081d43d4:	0x000055dff38bb240	0x08084cad08084b51
~~~
And `0x00002dc419c9e000` points to the rwx region. So, does overwriting this value give us PC control? Maybe we can use this PC control to ROP? Unfortunately, the answer is no. After a few trials, I still couldn't let V8 to dereference this pointer. After following the trace, @adamd and I found out that the real pointer used for invoking the shellcode resides on ptmalloc heap, which is outside of the cage.

Now what?

## Attempt 3
Now the only option left is to find a raw 64bit pointer on JS heap and hope that hijacking it can give us access to outside of the cage. But almost all values inside the cage are compressed pointers, how do we find 64bit pointers?

Oh wait, what are those in `WASMInstance`? Those are all 64bit pointers, lol. Let's just pick a good one.
To understand what those values stand for, the best approach is to do a `%DebugPrint`:
~~~
DebugPrint: 0x238b081d4325: [WasmInstanceObject] in OldSpace
 - map: 0x238b08206439 <Map(HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x238b08384bed <Object map = 0x238b08206c81>
 - elements: 0x238b08002249 <FixedArray[0]> [HOLEY_ELEMENTS]
 - module_object: 0x238b08084b51 <Module map = 0x238b082062d1>
 - exports_object: 0x238b08084cad <Object map = 0x238b08206e39>
 - native_context: 0x238b081c2c75 <NativeContext[266]>
 - memory_object: 0x238b081d430d <Memory map = 0x238b082066e1>
 - table 0: 0x238b08084c3d <Table map = 0x238b08206551>
 - imported_function_refs: 0x238b08002249 <FixedArray[0]>
 - indirect_function_table_refs: 0x238b08002249 <FixedArray[0]>
 - managed_native_allocations: 0x238b08084bf5 <Foreign>
 - managed object maps: 0x238b08002249 <FixedArray[0]>
 - feedback vectors: 0x238b08002249 <FixedArray[0]>
 - memory_start: 0x238c81010000
 - memory_size: 65536
 - imported_function_targets: 0x55dff38bbcd0
 - globals_start: (nil)
 - imported_mutable_globals: 0x55dff38bbcf0
 - indirect_function_table_size: 0
 - indirect_function_table_sig_ids: (nil)
 - indirect_function_table_targets: (nil)
 - properties: 0x238b08002249 <FixedArray[0]>
 - All own properties (excluding elements): {}
~~~
After printing the object, my attention was immediately drawn to `imported_function_targets` and `imported_mutable_global` because they are the only ptmalloc heap pointers in the printed result.

I had no idea what they were so I Googled `imported_mutable_global` first and found this snippet:
~~~
int index = num_imported_mutable_globals++;
instance->imported_mutable_globals_buffers()->set(index, *buffer);
// It is safe in this case to store the raw pointer to the buffer
// since the backing store of the JSArrayBuffer will not be
// relocated.
instance->imported_mutable_globals()[index] =
    reinterpret_cast<Address>(
        raw_buffer_ptr(buffer, global_object->offset()));
~~~
It seems like it is an array that stores all global variables used in the webassembly code. This is interesting, maybe we can overwrite the pointer and force the webassembly code to store globals somewhere else, potentially outside of the cage?

I checked the content of `imported_mutable_global` in memory and it was empty. This was because the sample webassembly did not use globals at all. So, I Googled again about how to write webassembly code, and specifically about how to use globals and then I came cross [this page](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WebAssembly/Global/Global). I copy-pasted the wat code from its [reference repo](https://github.com/mdn/webassembly-examples/blob/master/js-api-examples/global.wat) and compiled it into wasm using the [wabt](https://github.com/WebAssembly/wabt) toolkit and loaded the compiled wasm into my script. This small wasm basically implements the simple functionality to increase a global variable by 1.
The wat code is shown as follow:
~~~
(module
   (global $g (import "js" "global") (mut i32))
   (func (export "getGlobal") (result i32)
        (global.get $g))
   (func (export "incGlobal")
        (global.set $g
            (i32.add (global.get $g) (i32.const 1))))
)
~~~

Now we can use the following snippet to create a `WASMInstance` that uses globals:
~~~
var global = new WebAssembly.Global({value:'i64', mutable:true}, 0n);
var wasm_code = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 12, 3, 96, 0, 1, 126, 96, 0, 0, 96, 1, 126, 0, 2, 14, 1, 2, 106, 115, 6, 103, 108, 111, 98, 97, 108, 3, 126, 1, 3, 4, 3, 0, 1, 2, 7, 37, 3, 9, 103, 101, 116, 71, 108, 111, 98, 97, 108, 0, 0, 9, 105, 110, 99, 71, 108, 111, 98, 97, 108, 0, 1, 9, 115, 101, 116, 71, 108, 111, 98, 97, 108, 0, 2, 10, 23, 3, 4, 0, 35, 0, 11, 9, 0, 35, 0, 66, 1, 124, 36, 0, 11, 6, 0, 32, 0, 36, 0, 11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod, {js: {global}});
~~~
For experimentation, I overwrote `imported_mutable_global` to `0x4141414141414141` in the `WASMInstance` and invoke `wasm_instance.exports.incGlobal()`. And then, Crash!
![crash](https://github.com/Kyle-Kyle/blog/raw/master/_posts/resource/dice22/crash.png)

From the screenshot, we can clearly tell the V8 tries to treat our controlled value as an array pointer and load/store a value into where its first element points to. The most important thing here is that: everything is addressed in 64bit!!! No more cage!!!

Now things are easy, we first need to enhance our wat code. Instead of increasing the global value, we want it to store an arbitrary value into the global variable. This is implemented like this:
~~~
(module
   (global $g (import "js" "global") (mut i64))
   (func (export "getGlobal") (result i64)
        (global.get $g))
   (func (export "incGlobal")
        (global.set $g
            (i64.add (global.get $g) (i64.const 1))))
   (func (export "setGlobal") (param $p1 i64)
        (global.set $g (local.get $p1)))
)
~~~
Finally, we need to create a fake `imported_mutable_global` array. And remember, the first element in the array is the address where we can write to. Since we have full control over the cage, this fake array can be easily created inside the cage. And then we obtain a clean arbitrary write primitive:
~~~
function write4(addr, value) {
    arr3[victim_idx + 0x50/4] = addr & 0xffffffff;
    arr3[victim_idx + 0x50/4 + 1] = addr / 0x100000000;
    wasm_instance.exports.setGlobal(BigInt(value));
}
~~~
In the snippet, the first two lines prepare the 64bit out-of-cage pointer inside the fake array, the last line invoke the write and stores the value to the location.

Great! We now have arbitrary write primitive outside of the cage. At this point, we can say we successfully escape the cage.

# Arbitrary Write to Shellcode
Now things are clear. We can use the in-cage arbitrary read/write primitive to read out the address of the rwx region and then use the out-of-cage arbitrary write primitive to overwrite the code with our shellcode.

And then here is the flag: `dice{h0p-rop-pop-y0ur-w@y-out-of-the-sandb0x}`
The full exploits can be found [here](https://github.com/Kyle-Kyle/blog/blob/master/writeups/dice22_memory_hole).

# Conclusion
This challenge is just fun fun fun. I learnt and broke the "Virtual Memory Cage" protection in V8, which is exciting. And I also learnt a liiitle bit of webassembly. This may be a sign that I'm recovering from the PTSD about webassembly caused by a reversing challenge from a few years ago.

Oh btw, my solution is clearly not the intended solution as you can tell from the flag (which suggests ROP). The challenge author @chop0 told me that his approach involves overwriting "registerfile of a generator whilst it's suspended". I have no idea how it works and I'm eagerly waiting for his writeup. :D
