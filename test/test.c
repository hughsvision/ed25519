#include <stdio.h>
#include <string.h>
#include "sha512.h"

void print_charlist(unsigned char *list, int length){
    for(int i=0; i<length;i++) {
        printf("%d ",list[i]);
    }
    puts("\n");
}
int main() {

    unsigned char seed[32] = {118,232,213,67,126,97,12,170,23,115,35,172,202,113,73,254,73,155,243,18,101,70,17,24,150,118,243,223,10,57,246,6};
    SHA512_HASH digest;
    print_charlist(seed, 32);
    Sha512Calculate(seed, 32, &digest);
    for(int i=0; i<64; i++) {
        printf("%d ",digest.bytes[i]);
    }
    return 0;
}

