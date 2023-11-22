#include <stdint.h>
#include <string.h>

#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#define ASCON_128_KEYBYTES  16
#define ASCON_128_RATE      8
#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6

#define ASCON_128_IV                                                           \
    (((uint64_t) (ASCON_128_KEYBYTES * 8) << 56) |                             \
     ((uint64_t) (ASCON_128_RATE * 8) << 48) |                                 \
     ((uint64_t) (ASCON_128_PA_ROUNDS) << 40) |                                \
     ((uint64_t) (ASCON_128_PB_ROUNDS) << 32))

#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES    16

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

#define U64BIGENDIAN(x)                                                        \
    (((0x00000000000000FFULL & (x)) << 56) |                                   \
     ((0x000000000000FF00ULL & (x)) << 40) |                                   \
     ((0x0000000000FF0000ULL & (x)) << 24) |                                   \
     ((0x00000000FF000000ULL & (x)) << 8) |                                    \
     ((0x000000FF00000000ULL & (x)) >> 8) |                                    \
     ((0x0000FF0000000000ULL & (x)) >> 24) |                                   \
     ((0x00FF000000000000ULL & (x)) >> 40) |                                   \
     ((0xFF00000000000000ULL & (x)) >> 56))

#endif

typedef struct {
    uint64_t x[5];
} ascon_state_t;

/* function declarations */
static inline uint64_t LOADBYTES(const uint8_t *bytes, uint8_t n);
static inline void P6(ascon_state_t *s);
static inline void P12(ascon_state_t *s);
static inline uint64_t PAD(int i);
static inline uint64_t ROR(uint64_t x, int n);
static inline void ROUND(ascon_state_t *s, uint8_t C);
static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n);
static inline uint64_t U64_SWITCH_ENDIANESS(uint64_t x);
int ascon128_encrypt(unsigned char *c, unsigned long long *clen,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k, const unsigned char *n);

int ascon128_decrypt(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *c, unsigned long long clen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k, const unsigned char *n);

/* inline implementations */
static inline uint64_t LOADBYTES(const uint8_t *bytes, uint8_t n) {
    uint64_t x_little_endian = 0;
    memcpy(&x_little_endian, bytes, n);
    return U64_SWITCH_ENDIANESS(x_little_endian);   // to big endian
}

static inline void P6(ascon_state_t *s) {
    ROUND(s, RC6);
    ROUND(s, RC7);
    ROUND(s, RC8);
    ROUND(s, RC9);
    ROUND(s, RCa);
    ROUND(s, RCb);
}

static inline void P12(ascon_state_t *s) {
    ROUND(s, RC0);
    ROUND(s, RC1);
    ROUND(s, RC2);
    ROUND(s, RC3);
    ROUND(s, RC4);
    ROUND(s, RC5);
    ROUND(s, RC6);
    ROUND(s, RC7);
    ROUND(s, RC8);
    ROUND(s, RC9);
    ROUND(s, RCa);
    ROUND(s, RCb);
}

static inline uint64_t ROR(uint64_t x, int n) {
    return x >> n | x << (-n & 63);
}

static inline void ROUND(ascon_state_t *s, const uint8_t C) {
    ascon_state_t t;
    /* round constant layer */
    s->x[2] ^= C;
    /* substitution layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];
    /* linear diffusion layer */
    s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
}

static inline uint64_t PAD(int i) {
    return ((uint64_t) (0x80) << (56 - 8 * (i)));
}

/* store bytes from 64-bit Ascon word */
static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n) {
    uint64_t x_little_endian = U64_SWITCH_ENDIANESS(x);   // to little endian
    memcpy(bytes, &x_little_endian, n);
}

static inline uint64_t U64_SWITCH_ENDIANESS(uint64_t x) {
    return (((0x00000000000000FFULL & (x)) << 56) |
            ((0x000000000000FF00ULL & (x)) << 40) |
            ((0x0000000000FF0000ULL & (x)) << 24) |
            ((0x00000000FF000000ULL & (x)) << 8) |
            ((0x000000FF00000000ULL & (x)) >> 8) |
            ((0x0000FF0000000000ULL & (x)) >> 24) |
            ((0x00FF000000000000ULL & (x)) >> 40) |
            ((0xFF00000000000000ULL & (x)) >> 56));
}
