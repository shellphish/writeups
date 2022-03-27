# POC of ./chall logic. This python file ended up being too slow, but I added here for reference

addr_406060 = 0x00000000004012d1  
addr_406068 = 0x000000003b9aca07    # unchanged throughout the process
addr_406070 = 0x00000000004013f7    # unchanged throughout the process
addr_406078 = 0x00001009b375075f  
addr_406080 = 0x000010098eacdca4  
addr_406088 = 0x00000000004015b0    # unchanged throughout the process
addr_406050 = 0x0000100a6b70fcd0  
addr_406058 = 0x00001009b376ad6c  



def print_state():
    print("===================================")
    print("0x406050: 0x{:016X}".format(addr_406050))
    print("0x406058: 0x{:016X}".format(addr_406058))
    print("0x406060: 0x{:016X}".format(addr_406060))
    print("0x406068: 0x{:016X}".format(addr_406068))
    print("0x406070: 0x{:016X}".format(addr_406070))
    print("0x406078: 0x{:016X}".format(addr_406078))
    print("0x406080: 0x{:016X}".format(addr_406080))
    print("0x406088: 0x{:016X}".format(addr_406088))

def calculate_index(i1, i2):
    # some weird logic I didn't understand in the code.I recreated it by translating each line of assembly to python code
    tmp1 = i1 ^ i2
    tmp2 = (tmp1 * 0x5c9882b931057263) >> 0x40
    print(hex(tmp2))
    tmp3 = tmp1 - tmp2
    tmp4 = tmp3 >> 1                    # shr rax, 1
    tmp5 = tmp2 + tmp4                  # add rax, rdx
    tmp6 = tmp5 >> 5
    tmp7 = (tmp6 * 3 ) << 4
    tmp8 = tmp7 - tmp6
    tmp9 = tmp1 - tmp8
    assert(tmp9 < 0x50)
    assert(tmp9 >= 0)
    return tmp9

with open("log", 'w') as f:

    for i in range(1):
        addr_406060 = (addr_406060 * addr_406070) & (2**64-1)
        addr_406060 = addr_406060 % addr_406068
        if addr_406060 == addr_406088:
            break
   
        i = calculate_index(addr_406060, addr_406058)
        j = calculate_index(addr_406060, addr_406078)

        if i != j:
            ind = (addr_406080 ^ addr_406050) % 5
            if ind == 0:
                # print("add {:02X} to input[{}], subtract {:02X} from input[{}]".format(addr_406060 & 0xff, i, addr_406060 & 0xff, j))
                f.write("0, {}, {}, {}\n".format(i, j, addr_406060 & 0xff)) 
            elif ind == 1:
                # print("input[{}] = input[{}] ^ input[{}]".format(i, i, j))
                f.write("1, {}, {}\n".format(i, j))
            elif ind == 2:
                # print("input[{}] = input[{}] + input[{}]".format(i, i, j))
                f.write("2, {}, {}\n".format(i, j))
            elif ind == 3:
                # print("input[{}] = input[{}] - input[{}]".format(i, i, j))
                f.write("3, {}, {}\n".format(i, j))
            elif ind == 4:
                # print("swap input[{}] and input[{}]".format(i, j))
                f.write("4, {}, {}\n".format(i, j))

    
        addr_406058 = addr_406058 ^ addr_406080
        addr_406078 = addr_406078 ^ addr_406050
        addr_406058 = (addr_406058 * addr_406058) & (2**64-1)
        addr_406050 = (addr_406050 * addr_406058) & (2**64-1)
        addr_406050 = (addr_406050 + addr_406078) & (2**64-1)
        addr_406080 = (addr_406080 + addr_406050) & (2**64-1)
        print_state()
