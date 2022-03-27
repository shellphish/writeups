# Chirashi-Sushi

## Summary

The challenge asks for the flag as an input. It performs a series of reversible transformation on each byte and compares it with a hardcoded value in the binary. My solution is to collect a trace of the reversible operations and write a script to transform the hardcoded output back to its input. I used only ghidra and gdb to solve the challenge. 

## Solution

### Reversing initialization routine. 

I started by reversing the main function. The beginning of the main function looked very scary, but once I dug deeper into a function, I realized that those functions are just initializing a big structure in memory. 

Let's look at one of the initialization functions  

```C
int main() {
  ...
  local_94 = local_868;
  local_a4 = 0xfa1e0ff3;
  local_a0 = 0xbb49;
  local_9e = g_0.2562;
  local_96 = 0xba49;
  local_8c = 0x90e3ff49;
  ...
  f_X5f628f(&local_a4);
}
```
Those hardcoded hex numbers looked interesting to me, and in fact if you scan through main function, the numbers 0xfa1e0ff3 and 0xbb49 appears repeatedly! Let's take a look at the function `f_X5f628f`:

```C
void f_X5f628f(code *param_1) {
  ...
  local_18 = &stack0x00000008;
  local_28 = &local_38;
  local_38 = 0xfa1e0ff3;
  local_34 = 0xbb49;
  local_32 = f.2547;
  local_2a = 0xba49;
  local_20 = 0x90e3ff49;
  (*param_1)(&local_38);
  ...
}

```

Ahh so `local_a4` is meant to be interpreted as a function, which means those funny looking hex numbers are assembly! If we disassemble those funny hex numbers in the main function, we get:

```
# assembly in local_a4 in main
f3 0f 1e fa                 ENDBR64
49 bb <g_0.2562>            movabs r11, g_0.2562
49 ba <local_868>           movabs r10, local_868
49 ff e3 90                 jmp r11

# assembly in local_38 in f_X5f628f
f3 0f 1e fa                 ENDBR64
49 bb <f.2547>              movabs r11, f.2547
49 ba <local_38>            movabs r10, local_38
49 ff e3 90                 jmp r11

```

Let's continue to take a look at `f.2547` and `g_0.2562`:

```C
undefined8 * f.2547(void)

{
  return &X5f628f.2546;
}

void g_0.2562(code *param_1)

{
  undefined8 uVar1;
  long in_R10;
  
  uVar1 = (*param_1)();
  *(undefined8 *)(in_R10 + 0x1b8) = uVar1;
  return;
}

```

OK, so `f.2547` returns a pointer. In ghidra, that pointer points to an uninitialized global variable. On the other hand `g_0.2562` calls `param1` and then copies the return value of `param_1` into a variable offset-ed by 0x1b8. 

Now let's put everything together and see how it works

```
main called
    local_a4 = <assembly routine on stack that jumps to g_0 and sets r10=local_868>
    f_X5f628f(local_a4)
        local_38 = <another assembly routine on stack that jumps to f.2547 and sets r10=local_38>
        local_a4(local_38)
            sets r10=local_868 in main
            jumps to g_0.2562
                calls assembly routine in local_38
                    sets r10 = local_38
                    jumps to f.2547
                        return &X5f628f.2546
                sets local_868+0x1b8=&X5f628f.2546 (local_868 = r10)
                returns to f_X5f628f
    return to main        
            
```
From here I see two things:

1. `local_868` is a structure that is at least 0x1c0 long. 
2. This complicated logic essentially sets a variable in main to a pointer to a global variable. I scan through the other functions and took a leap of faith that those functions do something similar, i.e. they fill in different fields of `local_868`. 

With these two hypothesis in mind, I created a structure of size 0x1c0 in `local_868`, and assumed all the fields in `local_868` to be pointers. And here is what I got

```C
int main() {
  *local_868.field_0xf8 = 0x3b9aca07;
  *local_868.field_0x118 = (long)f_Xcefe37;
  *local_868.field_0xc8 = (long)f_X88417a;
  *local_868.field_0x1a8 = (long)f_X5bab1c;
  *local_868.field_0xf0 = 0x1009b376ad6c;
  *local_868.field_0xd8 = 0x1009b375075f;
  *local_868.field_0xb0 = 0x10098eacdca4;
  *local_868.field_0x128 = 0x100a6b70fcd0;
  input._0_8_ = 0;
  input._8_8_ = 0;
  input._16_8_ = 0;
  input._24_8_ = 0;
  input._32_8_ = 0;
  input._40_8_ = 0;
  __isoc99_scanf("%47s",input);
  while( true ) {
    *local_868.field_0x0 = *local_868.field_0x0 * *local_868.field_0x130;
    *local_868.field_0x158 = *local_868.field_0x158 % *local_868.field_0x50;
    if (*local_868.field_0x108 == *local_868.field_0x160) break;
    uVar1 = *local_868.field_0x68 ^ *local_868.field_0x20;
    lVar4 = SUB168(ZEXT816(uVar1) * ZEXT816(0x5c9882b931057263) >> 0x40,0);
    iVar2 = (int)uVar1 + (int)((uVar1 - lVar4 >> 1) + lVar4 >> 5) * -0x2f;
    uVar1 = *local_868.field_0x178 ^ *local_868.field_0x70;
    lVar4 = SUB168(ZEXT816(uVar1) * ZEXT816(0x5c9882b931057263) >> 0x40,0);
    iVar3 = (int)uVar1 + (int)((uVar1 - lVar4 >> 1) + lVar4 >> 5) * -0x2f;
    if (iVar2 != iVar3) {
      switch((ulong)(*local_868.field_0xc0 ^ *local_868.field_0x30) % 5) {
      case 0:
        input[iVar2] = input[iVar2] + (char)*local_868.field_0x120;
        input[iVar3] = input[iVar3] - (char)*local_868.field_0x80;
        break;
      case 1:
        input[iVar2] = input[iVar2] ^ input[iVar3];
        break;
      case 2:
        input[iVar2] = input[iVar2] + input[iVar3];
        break;
      case 3:
        input[iVar2] = input[iVar2] - input[iVar3];
        break;
      case 4:
        input[iVar2] = input[iVar2] ^ input[iVar3];
        input[iVar3] = input[iVar3] ^ input[iVar2];
        input[iVar2] = input[iVar2] ^ input[iVar3];
      }
    }
    *local_868.field_0x170 = *local_868.field_0x170 ^ *local_868.field_0x148;
    *local_868.field_0x168 = *local_868.field_0x168 ^ *local_868.field_0x58;
    *local_868.field_0x140 = *local_868.field_0x140 * *local_868.field_0x28;
    *local_868.field_0x48 = *local_868.field_0x48 * *local_868.field_0x1a0;
    *local_868.field_0x110 = *local_868.field_0x110 + *local_868.field_0x190;
    *local_868.field_0x1b8 = *local_868.field_0x1b8 + *local_868.field_0x198;
  }
  ...
}

``` 

### Reversing the input transform logic 

My first thought was, oh no! There's so many fields to keep track of and reverse! I did spend quite a while trying to statically figure out what each field represents, but at the end, I pulled out my trusty debugger and realized the fields were just illusions:

```
pwndbg> x/56gx $rbp-0x860
0x7fffffffd6e0: 0x0000000000406060  0x0000000000406078 
0x7fffffffd6f0: 0x0000000000406080  0x0000000000406080  
0x7fffffffd700: 0x0000000000406058  0x0000000000406058  
0x7fffffffd710: 0x0000000000406050  0x0000000000406080  
0x7fffffffd720: 0x0000000000406088  0x0000000000406050  
0x7fffffffd730: 0x0000000000406068  0x0000000000406050 
0x7fffffffd740: 0x0000000000406080  0x0000000000406060  
0x7fffffffd750: 0x0000000000406078  0x0000000000406070  
0x7fffffffd760: 0x0000000000406060  0x0000000000406088  
0x7fffffffd770: 0x0000000000406080  0x0000000000406070  
0x7fffffffd780: 0x0000000000406060  0x0000000000406050  
0x7fffffffd790: 0x0000000000406080  0x0000000000406068  
0x7fffffffd7a0: 0x0000000000406080  0x0000000000406070  
0x7fffffffd7b0: 0x0000000000406080  0x0000000000406078  
0x7fffffffd7c0: 0x0000000000406080  0x0000000000406080  
0x7fffffffd7d0: 0x0000000000406058  0x0000000000406068  
0x7fffffffd7e0: 0x0000000000406080  0x0000000000406060  
0x7fffffffd7f0: 0x0000000000406050  0x0000000000406060  
0x7fffffffd800: 0x0000000000406060  0x0000000000406050  
0x7fffffffd810: 0x0000000000406070  0x0000000000406080  
0x7fffffffd820: 0x0000000000406058  0x0000000000406080  
0x7fffffffd830: 0x0000000000406058  0x0000000000406060  
0x7fffffffd840: 0x0000000000406088  0x0000000000406078  
0x7fffffffd850: 0x0000000000406058  0x0000000000406060  
0x7fffffffd860: 0x0000000000406080  0x0000000000406060  
0x7fffffffd870: 0x0000000000406078  0x0000000000406050  
0x7fffffffd880: 0x0000000000406058  0x0000000000406088  
0x7fffffffd890: 0x0000000000406080  0x0000000000406080

```

All the fields in the `local_868` structure are simply aliases to the same 6 memory addresses! So I proceeded to map all the fields to their corresponding addresses, and got this much nicer looking decompilation 

```C
int main() {
  ...
  *addr_406068 = 0x3b9aca07;
  *addr_406060 = (long)f_Xcefe37;
  *addr_406070 = (long)f_X88417a;
  *addr_406088 = (long)f_X5bab1c;
  *addr_406058 = 0x1009b376ad6c;
  *addr_406078 = 0x1009b375075f;
  *addr_406080 = 0x10098eacdca4;
  *addr_406050 = 0x100a6b70fcd0;

  while( true ) {
    *addr_406060 = *addr_406060 * *addr_406070;
    *addr_406060 = *addr_406060 % *addr_406068;
    if (*addr_406060 == *addr_406088) break;
    uVar1 = *addr_406060 ^ *addr_406058;
    lVar4 = SUB168(ZEXT816(uVar1) * ZEXT816(0x5c9882b931057263) >> 0x40,0);
    iVar2 = (int)uVar1 + (int)((uVar1 - lVar4 >> 1) + lVar4 >> 5) * -0x2f;
    uVar1 = *addr_406060 ^ *addr_406078;
    lVar4 = SUB168(ZEXT816(uVar1) * ZEXT816(0x5c9882b931057263) >> 0x40,0);
    iVar3 = (int)uVar1 + (int)((uVar1 - lVar4 >> 1) + lVar4 >> 5) * -0x2f;
    if (iVar2 != iVar3) {
      switch((ulong)(*addr_406080 ^ *addr_406050) % 5) {
      case 0:
        input[iVar2] = input[iVar2] + (char)*addr_406060;
        input[iVar3] = input[iVar3] - (char)*addr_406060;
        break;
      case 1:
        input[iVar2] = input[iVar2] ^ input[iVar3];
        break;
      case 2:
        input[iVar2] = input[iVar2] + input[iVar3];
        break;
      case 3:
        input[iVar2] = input[iVar2] - input[iVar3];
        break;
      case 4:
        input[iVar2] = input[iVar2] ^ input[iVar3];
        input[iVar3] = input[iVar3] ^ input[iVar2];
        input[iVar2] = input[iVar2] ^ input[iVar3];
      }
    }
    *addr_406058 = *addr_406058 ^ *addr_406080;
    *addr_406078 = *addr_406078 ^ *addr_406050;
    *addr_406058 = *addr_406058 * *addr_406058;
    *addr_406050 = *addr_406050 * *addr_406058;
    *addr_406050 = *addr_406050 + *addr_406078;
    *addr_406080 = *addr_406080 + *addr_406050;
  }

}
```

Here's what I see from this decompilation:
1. The program initialize the global variables to some hex numbers
2. In the while loop, the global variables are used to compute some state that determines what we do with the input. It can add or subtract a global value from the input (case 0), XOR the input bytes (case 1), add (case 2) or subtract (case 3) bytes within the input or swap the input bytes (case 4). 
3. The global variables are updated

The global variables are essentially used to create a state machine, and the good thing about it is that the global variables are completely independent of the input. Moreover, all the operations on the input bytes are completely reversible, meaning that if we can recreate a trace of the state machine, we can reverse the trace and obtain the original inputs back from its outputs. Lucky for us, the outputs are also hardcoded in the main function 

```C
  output._0_8_ = 0x97d54fbb1a8b7e3b;
  output._8_8_ = 0x87fd66cbcfbe80a5;
  output._16_8_ = 0xe80de41a07115875;
  output._24_8_ = 0xa50860421721908b;
  output._32_8_ = 0x7aa2645a89a03af8;
  output._40_8_ = 0x392438a7e2307d;
  iVar2 = memcmp(input,output,0x2f);
  if (iVar2 == 0) {
    puts("correct");
  }
```

### Creating the trace

This part is not too difficult. We can use the above pseudo code to recreate the logic in Python. I'll admit that I do not know what these two lines do

```C
    lVar4 = SUB168(ZEXT816(uVar1) * ZEXT816(0x5c9882b931057263) >> 0x40,0);
    iVar3 = (int)uVar1 + (int)((uVar1 - lVar4 >> 1) + lVar4 >> 5) * -0x2f;
```

My best guess is that this is some division optimization that turns the division into a multiplication, but I ended up recreating the logic line by line base on the assembly. 

However, once I ran my python script (poc.py), I realize that it is taking way tooo long, to the point where I thought my program hanged. I tried to create a gdb tracer and the result is still the same. So I ended up converting everything to C (trace.c) and ran that script. Luckily, trace.c ran within one minute, and I got a trace that is 5GB long! I reversed the trace, pass it through soln.c, which is meant to reverse all the operations in trace.c, and obtained the flag in the end. 


## Flag

```
zer0pts{sc4110p_1s_my_m05t_fav0r1t3_su5h1_1t3m}
```
