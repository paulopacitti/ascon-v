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

#define RC0 0xf0
#define RC1 0xe1
#define RC2 0xd2
#define RC3 0xc3
#define RC4 0xb4
#define RC5 0xa5
#define RC6 0x96
#define RC7 0x87
#define RC8 0x78
#define RC9 0x69
#define RCa 0x5a
#define RCb 0x4b

#endif

typedef struct {
    uint64_t x[5];
} ascon_state_t;

uint64_t SETBYTE(const uint8_t b, int i);
uint64_t ROR(uint64_t x, int n);
void ROUND(ascon_state_t *s, uint8_t C);
void P6(ascon_state_t *s);
void P12(ascon_state_t *s);

int ascon128_encrypt(unsigned char *c, unsigned long long *clen,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k);