// creates trace of ./chall

#include <stdio.h>
#include <stdlib.h>

unsigned long long addr_406060 = 0x00000000004012d1;
unsigned long long addr_406068 = 0x000000003b9aca07;
unsigned long long addr_406070 = 0x00000000004013f7;
unsigned long long addr_406078 = 0x00001009b375075f;
unsigned long long addr_406080 = 0x000010098eacdca4;
unsigned long long addr_406088 = 0x00000000004015b0;
unsigned long long addr_406050 = 0x0000100a6b70fcd0;
unsigned long long addr_406058 = 0x00001009b376ad6c;

void print_state() {
    printf("0x406050: %llx\n", addr_406050);
    printf("0x406058: %llx\n", addr_406058);
    printf("0x406060: %llx\n", addr_406060);
    printf("0x406068: %llx\n", addr_406068);
    printf("0x406070: %llx\n", addr_406070);
    printf("0x406078: %llx\n", addr_406078);
    printf("0x406080: %llx\n", addr_406080);
    printf("0x406088: %llx\n", addr_406088);

}


unsigned int calculate_index(unsigned long long i1, unsigned long long i2) {
    unsigned long long tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
    tmp1 = i1 ^ i2;
    __asm__(
        "movabsq $0x5c9882b931057263, %%rdx;\n"
        "mov %1, %%rax;\n"
        "mul %%rdx;\n"
        "mov %%rdx, %0\n" 
        : "=r" (tmp2) // output
        : "r" (tmp1)    // input
        : "rdx", "rax","rcx"
    );
    // tmp2 = (tmp1 * 0x5c9882b931057263) >> 0x40;
    tmp3 = tmp1 - tmp2;
    tmp4 = tmp3 >> 1;
    tmp5 = tmp2 + tmp4;
    tmp6 = tmp5 >> 5;
    tmp7 = (tmp6 * 3) << 4;
    tmp8 = tmp7-tmp6;
    tmp9 = tmp1-tmp8;
    if (tmp9 > 0x50) {
        printf("tmp9 is too large, exiting\n");
        exit(-1);
    }
    return tmp9;
}

int main() {

    while(1) {

        addr_406060 = addr_406060 * addr_406070;
        addr_406060 = addr_406060 % addr_406068;

        if (addr_406060 == addr_406088)
            break;

        unsigned int i = calculate_index(addr_406060, addr_406058);
        unsigned int j = calculate_index(addr_406060, addr_406078);

        // The printfs prints out the trace for soln.c to parse
        if (i != j) {
            unsigned int ind = (addr_406080 ^ addr_406050) % 5;
            if (ind == 0) {
                printf("0, %d, %d, %d\n", i, j, addr_406060 & 0xff);
            } else if (ind == 1) {
                printf("1, %d, %d\n", i, j);
            } else if (ind == 2) {
                printf("2, %d, %d\n", i, j);
            } else if (ind == 3) {
                printf("3, %d, %d\n", i, j);
            } else if (ind == 4) {
                printf("4, %d, %d\n", i, j);
            } else {
                printf("%d\n", ind);
            }
        }

        addr_406058 = addr_406058 ^ addr_406080;
        addr_406078 = addr_406078 ^ addr_406050;
        addr_406058 = addr_406058 * addr_406058;
        addr_406050 = addr_406050 * addr_406058;
        addr_406050 = addr_406050 + addr_406078;
        addr_406080 = addr_406080 + addr_406050;
        // print_state();
        // printf("=========================\n");
    }
    return 0;
}
