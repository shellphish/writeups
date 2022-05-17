import json

import claripy


def neg(a):
    return 1 if a == 0 else 0

def identity(a):
    return a

first_step_array = [
    neg,  identity,  identity,  neg,
    identity,  identity,  neg,  identity,
    identity,  identity,  neg,  neg,
    identity,  identity,  identity,  identity,
    neg,  neg,  identity,  identity,
    identity,  identity,  neg,  identity,
    neg,  identity,  neg,  neg,
    neg,  neg,  neg,  identity,
    neg,  identity,  identity,  identity,
    neg,  neg,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    identity,  identity,  identity,  identity,
    identity,  identity,  neg,  neg,
    neg,  identity,  identity,  identity,
    identity,  identity,  identity,  identity,
    neg,  neg,  identity,  identity,
    neg,  identity,  neg,  neg,
    identity,  identity,  identity,  neg,
    identity,  neg,  identity,  identity,
    neg,  neg,  identity,  neg,
    identity,  identity,  identity,  neg,
    neg,  neg,  identity,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  identity,  neg,  neg,
    neg,  neg,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    identity,  neg,  identity,  neg,
    neg,  identity,  identity,  neg,
    identity,  neg,  identity,  neg,
    neg,  identity,  neg,  neg,
    neg,  identity,  identity,  identity,
    neg,  neg,  identity,  neg,
    neg,  neg,  neg,  neg,  neg,
    neg,  neg,  neg,  neg,  neg,
    identity,  identity,  identity,  neg,
    identity,  identity,  neg,  neg,
    neg,  neg,  identity,  identity,
    identity,  identity,  identity,  identity,
    neg,  identity,  neg,  identity,
    identity,  identity,  neg,  identity,
    identity,  neg,  neg,  identity,
    neg,  identity,  identity,  neg,
    identity,  identity,  neg,  identity,
    identity,  identity,  neg,  identity,
    neg,  neg,  neg,  identity,
    neg,  identity,  neg,  neg,
    neg,  identity,  identity,  identity,
    identity,  neg,  identity,  identity,
    neg,  identity,  identity,  neg,
    identity,  identity,  identity,  identity,
    identity,  identity,  neg,  identity,
    neg,  identity,  identity,  identity,
    neg,  identity,  identity,  neg,
    neg,  identity,  identity,  neg,
    identity,  neg,  neg,  identity,
    identity,  identity,  neg,  identity,
    identity,  neg,  neg,  neg,
    identity,  identity,  identity,  neg,
    neg,  identity,  neg,  neg,
    neg,  identity,  neg,  neg,
    neg,  neg,  neg,  identity,
    neg,  neg,  identity,  identity,
    neg,  identity,  identity,  neg,
    neg,  identity,  neg,  identity,
    identity,  neg,  identity,  neg,
    neg,  identity,  neg,  identity,
    neg,  neg,  neg,  identity,
    neg,  identity,  identity,  neg,
    identity,  neg,  neg,  identity,
    neg,  neg,  identity,  neg,
    neg,  identity,  identity,  neg,
    neg,  neg,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    neg,  identity,  neg,  identity,
    identity,  neg,  neg,  identity,
    neg,  identity,  identity,  neg,
    identity,  neg,  neg,  identity,
    identity,  neg,  neg,  neg,
    neg,  identity,  identity,  neg,
    neg,  identity,  identity,  neg,
    identity,  neg,  neg,  neg,
    identity,  neg,  identity,  neg,
    neg,  identity,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  identity,  neg,  neg,
    identity,  neg,  identity,  identity,
    neg,  neg,  identity,  identity,
    identity,  identity,  identity,  neg,
    neg,  identity,  identity,  identity,
    identity,  neg,  identity,  neg,
    identity,  identity,  identity,  neg,
    identity,  identity,  identity,  identity,
    identity,  identity,  neg,  neg,
    neg,  identity,  identity,  identity,
    identity,  neg,  neg,  identity,
    identity,  identity,  identity,  identity,
    identity,  identity,  neg,  neg,
    neg,  neg,  identity,  identity,
    neg,  identity,  identity,  identity,
    identity,  identity,  neg,  identity,
    neg,  neg,  identity,  identity,
    neg,  identity,  neg,  identity,
    identity,  identity,  identity,  identity,
    neg,  identity,  identity,  identity,
    identity,  identity,  identity,  neg,
    identity,  identity,  identity,  neg,
    neg,  neg,  identity,  identity,
    identity,  neg,  neg,  identity,
    identity,  neg,  identity,  neg,
    identity,  neg,  identity,  neg,
    identity,  neg,  identity,  identity,
    identity,  neg,  neg,  identity,
    neg,  neg,  identity,  neg,
    neg,  identity,  neg,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  neg,  neg,  neg,
    identity,  neg,  neg,  identity,
    identity,  neg,  identity,  neg,
    identity,  identity,  identity,  neg,
    identity,  identity,  neg,  neg,
    neg,  identity,  identity,  identity,
    neg,  neg,  neg,  identity,
    identity,  identity,  identity,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  neg,  neg,  neg,
    identity,  neg,  neg,  neg,
    neg,  identity,  neg,  identity,
    neg,  neg,  neg,  identity,
    identity,  neg,  identity,  identity,
    neg,  neg,  identity,  identity,
    identity,  identity,  neg,  identity,
    neg,  neg,  identity,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  neg,  neg,  neg,
    identity,  neg,  identity,  neg,
    identity,  neg,  neg,  neg,
    identity,  neg,  identity,  neg,
    identity,  identity,  neg,  identity,
    neg,  neg,  identity,  identity,
    neg,  identity,  neg,  identity,
    neg,  neg,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    neg,  neg,  neg,  identity,
    identity,  neg,  identity,  identity,
    identity,  neg,  identity,  neg,
    identity,  identity,  identity,  identity,
    identity,  neg,  neg,  identity,
    neg,  identity,  identity,  neg,
    neg,  identity,  identity,  neg,
    identity,  identity,  identity,  identity,
    identity,  neg,  identity,  identity,
    identity,  identity,  identity,  identity,
    identity,  neg,  neg,  neg,
    neg,  neg,  identity,  neg,
    neg,  identity,  identity,  identity,
    neg,  neg,  identity,  identity,
    neg,  neg,  neg,  neg,  identity,
    identity,  neg,  identity,  neg,
    identity,  identity,  identity,  neg,
    identity,  neg,  identity,  identity,
    identity,  identity,  neg,  neg,
    identity,  identity,  neg,  identity,
    neg,  neg,  identity,  identity,
    neg,  identity,  identity,  neg,
    neg,  neg,  neg,  neg,  identity,
    neg,  neg,  neg,  neg,  identity,
    neg,  identity,  neg,  identity,
    neg,  neg,  neg,  identity,
    neg,  identity,  identity,  identity,
    identity,  neg,  neg,  identity,
    neg,  identity,  identity,  neg,
    neg,  identity,  identity,  neg,
    neg,  neg,  identity,  neg,
    neg,  neg,  identity,  neg,
    identity,  neg,  neg,  identity,
    neg,  neg,  identity,  identity,
    identity,  neg,  neg,  neg,
    identity,  identity,  identity,  neg,
    identity,  neg,  neg,  identity,
    neg,  neg,  identity,  neg,
    neg,  identity,  neg,  identity,
    neg,  neg,  neg,  neg,  neg,
    neg,  neg,  neg,  neg,  neg,
    neg,  neg,  identity,  neg,
    identity,  neg,  identity,  neg,
    identity,  neg,  identity,  neg,
    identity,  identity,  neg,
]

flag = [0,   1,   1,   0,   1,   1,   1,   0,   0,   1, 
    1,   0,   1,   1,   1,   1,   0,   1,   1,   1, 
    0,   1,   0,   0,   0,   1,   1,   0,   0,   1, 
    1,   0,   0,   1,   1,   0,   1,   1,   0,   0, 
    0,   1,   1,   0,   0,   0,   0,   1,   0,   1, 
    1,   0,   0,   1,   1,   1,   0,   0,   1,   0, 
    0,   0,   0,   1]

chains = [
  62,
  56,
  8,
  39,
  24,
  43,
  7,
  11,
  20,
  61,
  22,
  58,
  53,
  18,
  41,
  3,
  48,
  59,
  23,
  9,
  46,
  63,
  6,
  2,
  26,
  25,
  55,
  0,
  60,
  54,
  32,
  12,
  28,
  42,
  15,
  10,
  38,
  50,
  5,
  52,
  27,
  47,
  37,
  13,
  21,
  14,
  49,
  57,
  45,
  19,
  29,
  44,
  34,
  40,
  16,
  33,
  36,
  30,
  17,
  31,
  1,
  35,
  51,
  4]

def encoder(input, flag):
    if input >= 0x40:
        print("Error, input too large")
        return

    input_bits = [0]*6
    for i in range(6):
        input_bits[5-i] = input & 1
        input >>= 1

    #print(input_bits)
    first_output = first_step(input_bits)
    #print(first_output)
    second_output = second_step(first_output, flag)
    #print(second_output)
    third_output = third_step(second_output)

    #print(third_output)
    return third_output

def encoder_symbolic(input, flag):
    assert(input < 0x40)

    input_bits = [0]*6
    for i in range(6):
        input_bits[5-i] = claripy.BVV(input & 1, size=1)
        input >>= 1

    first_output = first_step_symbolic(input_bits)
    second_output = second_step(first_output, flag)
    third_output = third_step(second_output)

    return third_output

def first_step(input_bits):
    to_return = []
    for i in range(64):
        val = 0
        for j in range(2):
            cur = 1
            for k in range(6):
                func = first_step_array[12*i + 6*j + k]
                cur &= func(input_bits[k])
            val |= cur
        to_return.append(val)
    return to_return

def first_step_symbolic(input_bits):
    to_return = []
    for i in range(64):
        val = claripy.BVV(0, size=1)
        for j in range(2):
            cur = claripy.BVV(1, size=1)
            for k in range(6):
                func = first_step_array[12*i + 6*j + k]
                this_val = input_bits[k]
                if func == neg:
                    this_val = this_val ^ 1
                cur &= this_val
            val |= cur
        to_return.append(val)
    return to_return
    

def second_step(buf, flag):
    to_return = []
    for i in range(64):
        to_return.append(buf[i] & flag[i])
    return to_return

def third_step(buf):
    output = 0
    for i in range(8):
        tmp = [0]*8
        for j in range(8):
            tmp[j] = buf[chains[8*i + ((j+1) % 8)]] & buf[chains[8*i + j]]
        output |= tmp[0] | tmp[1] | tmp[2] | tmp[3] | tmp[4] | tmp[5] | tmp[6] | tmp[7]

    return output

if __name__ == "__main__":
    #print(encoder(int(val), flag))

    with open("./output.txt") as f:
        required = json.load(f)

    s = claripy.Solver()
    flag = claripy.BVS(f"flag", 64)

    # Add constraints regarding the flag
    for i in range(0, 64, 8):
        flag_byte = flag[i+7:i]
        s.add(flag_byte >= 0x20)
        s.add(flag_byte <= 0x7E)

    
    flag_array = []
    for i in range(63, -1, -1):
         flag_array.append(flag[i])

    print(flag_array)
    import ipdb; ipdb.set_trace()

    equations = []
    for r in required:
        equation = encoder_symbolic(r["input"], flag_array)
        equations.append(equation == r["output"])

    final = claripy.And(*equations)
    s.add(final)

    real_flag = []
    flags = s.eval(flag, 100)
    print(len(flags))
    for possible_flag in flags:

        candidate_flag = ""
        for i in range(8):
            candidate_flag += chr(possible_flag & 0xFF)
            possible_flag >>= 8
        
        print(candidate_flag[::-1])
