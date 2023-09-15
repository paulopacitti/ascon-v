#include <stdint.h>

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#define ASCON_128_KEYBYTES   16
#define ASCON_128_RATE       8
#define ASCON_128_PA_ROUNDS  12
#define ASCON_128_PB_ROUNDS  6
#define ASCON_128A_PA_ROUNDS 12
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_128_IV                                                           \
    (((uint64_t) (ASCON_128_KEYBYTES * 8) << 56) |                             \
     ((uint64_t) (ASCON_128_RATE * 8) << 48) |                                 \
     ((uint64_t) (ASCON_128_PA_ROUNDS) << 40) |                                \
     ((uint64_t) (ASCON_128_PB_ROUNDS) << 32))

#endif

typedef struct {
    uint64_t x[5];
} ascon_state_t;

/* load bytes into 64-bit Ascon word */
uint64_t LOADBYTES(const uint8_t *bytes, int n);
/* set byte in 64-bit Ascon word */
uint64_t SETBYTE(const uint8_t b, int i);
uint64_t ROR(uint64_t x, int n);
void ROUND(ascon_state_t *s, uint8_t C);

int ascon_aead_encrypt(unsigned char *c, unsigned long long *clen,
                       const unsigned char *m, unsigned long long mlen,
                       const unsigned char *ad, unsigned long long adlen,
                       const unsigned char *nsec, const unsigned char *npub,
                       const unsigned char *k);

int ascon_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                       unsigned char *nsec, const unsigned char *c,
                       unsigned long long clen, const unsigned char *ad,
                       unsigned long long adlen, const unsigned char *npub,
                       const unsigned char *k);