// Takes in the reversed trace (pass the output of trace.c through tac) and reverse all the operations in the trace.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {

    unsigned char result[47] = {
        0x3b, 0x7e, 0x8b, 0x1a, 0xbb, 0x4f, 0xd5, 0x97,
        0xa5, 0x80, 0xbe, 0xcf, 0xcb, 0x66, 0xfd, 0x87, 
        0x75, 0x58, 0x11, 0x07, 0x1a, 0xe4, 0x0d, 0xe8,
        0x8b, 0x90, 0x21, 0x17, 0x42, 0x60, 0x08, 0xa5,
        0xf8, 0x3a, 0xa0, 0x89, 0x5a, 0x64, 0xa2, 0x7a,
        0x7d, 0x30, 0xe2, 0xa7, 0x38, 0x24, 0x39
    };


    // parse the file
    FILE *fd = fopen("trace_rev.txt", "r");
    char line[256];
    while (fgets(line, sizeof(line), fd)) {
        char *pt;
        pt = strtok(line, ",");
        int code = atoi(pt);
        pt = strtok(0, ",");
        int i = atoi(pt);
        pt = strtok(0, ",");
        int j = atoi(pt);
     
        if (i >= 47 || j >= 47) {
            printf("Unreasonable i or j\n");
            exit(-1);
        }

        if (code == 0) {
            pt = strtok(0, ",");
            unsigned char a = atoi(pt);
           
            result[i] = result[i] - a;
            result[j] = result[j] + a;
        } else if (code == 1) {
            result[i] = result[i] ^ result[j];
        } else if (code == 2) {
            // in[i] = in[i] + in[j];
            result[i] = result[i] - result[j];
        } else if (code == 3) {
            // in[i] = in[i] - in[j]
            result[i] = result[i] + result[j]; 
        } else {
            // swap i and j
            unsigned char tmp;
            tmp = result[i];
            result[i] = result[j];
            result[j] = tmp;
        } 
    
    }

    fclose(fd);

    for (int i = 0 ; i < 47; i++) {
        printf("%x\n", result[i]);
    }



    return 0;

}
