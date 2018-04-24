#include <stdio.h>
#include <string.h>
#include "sha512.h"
#include "ed25519.h"

void print_charlist(unsigned char *list, int length){
    for(int i=0; i<length;i++) {
        printf("%d ",list[i]);
    }
    puts("\n");
}
int test_sha512_hash() {

    unsigned char seed[32] = {118,232,213,67,126,97,12,170,23,115,35,172,202,113,73,254,73,155,243,18,101,70,17,24,150,118,243,223,10,57,246,6};
    SHA512_HASH digest;
    print_charlist(seed, 32);
    Sha512Calculate(seed, 32, &digest);
    for(int i=0; i<64; i++) {
        printf("%d ",digest.bytes[i]);
    }
    return 0;
}

int test_keypair() {

    return 0;
}

int test_sign_and_verify() {
    unsigned char seed[32] = {114,185,233,83,24,8,249,111,109,189,187,81,200,247,45,254,211,130,123,236,
      124,110,55,77,43,66,74,58,25,253,230,184};
    unsigned char public[32];
    unsigned char secret[64];
    unsigned char message[12]={116,101,115,116,32,109,101,115,115,97,103,101};
    unsigned char signature[64];
    print_charlist(seed, 32);
    ed25519_create_keypair(public, secret, seed);
    print_charlist(public, 32);
    ed25519_sign(signature, message, 12, secret);
    if(ed25519_verify(signature, message, 12, public)) {
        puts("pass");
    }else{
        puts("not pass");
    }
    print_charlist(signature, 64);
    return 0;
}

int main() {
    test_sign_and_verify();
    return 0;
}
