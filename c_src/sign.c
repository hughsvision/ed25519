#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"


int ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len,  const unsigned char *private_key) {
    Sha512Context hash;
    unsigned char hram[64];
    unsigned char reduce[64];
    SHA512_HASH digest;
    SHA512_HASH digest1;
    unsigned char expanded_secret_key[32];
    ge_p3 R;

    Sha512Initialise(&hash);
    Sha512Update(&hash, private_key, 32);
    Sha512Finalise(&hash,&digest1);
    for(int i=0; i<32 ; i++) {
        expanded_secret_key[i] = digest1.bytes[i];
    }
    //memmove(expanded_secret_key, &digest1.bytes, 32); 
    expanded_secret_key[0] &= 248;
    expanded_secret_key[31] &= 63;
    expanded_secret_key[31] |= 64;

    Sha512Initialise(&hash);
    Sha512Update(&hash, digest1.bytes + 32, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, &digest);
    for( int j=0; j<64; j++) {
        reduce[j] = digest.bytes[j];
    }
    sc_reduce(reduce);
    ge_scalarmult_base(&R, reduce);
    ge_p3_tobytes(signature, &R);

    Sha512Initialise(&hash);
    Sha512Update(&hash, signature, 32);
    Sha512Update(&hash, private_key+32, 32);
    Sha512Update(&hash, message, message_len);
    Sha512Finalise(&hash, hram);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, expanded_secret_key, reduce);
    return 0;
}
