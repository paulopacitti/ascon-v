#include "asconv.h"

uint8_t GETBYTE(uint64_t x, uint8_t i) {
    return (uint8_t) ((uint64_t) (x) >> (56 - 8 * (i)));
}

uint64_t LOADBYTES(const uint8_t *bytes, uint8_t n) {
    int i;   // max key lenght is 128 bits
    uint64_t x = 0;
    for (i = 0; i < n; ++i)
        x |= SETBYTE(bytes[i], i);
    return x;
}

/* store bytes from 64-bit Ascon word */
void STOREBYTES(uint8_t *bytes, uint64_t x, int n) {
    int i;
    for (i = 0; i < n; ++i)
        bytes[i] = GETBYTE(x, i);
}

uint64_t SETBYTE(const uint8_t b, int i) {
    return ((uint64_t) (b) << (56 - 8 * (i)));
}

uint64_t ROR(uint64_t x, int n) { return x >> n | x << (-n & 63); }

void ROUND(ascon_state_t *s, const uint8_t C) {
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

void P6(ascon_state_t *s) {
    ROUND(s, RC6);
    ROUND(s, RC7);
    ROUND(s, RC8);
    ROUND(s, RC9);
    ROUND(s, RCa);
    ROUND(s, RCb);
}

void P12(ascon_state_t *s) {
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

int ascon128_encrypt(unsigned char *c, unsigned long long *clen,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k, const unsigned char *n) {
    ascon_state_t s;
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    const uint64_t N0 = LOADBYTES(n, 8);
    const uint64_t N1 = LOADBYTES(n + 8, 8);

    /* initialization */
    s.x[0] = ASCON_128_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;

    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    /* process additional data */
    if (adlen) {
        while (adlen >= ASCON_128_RATE) {
            s.x[0] ^= LOADBYTES(ad, ASCON_128_RATE);
            P6(&s);
            ad += ASCON_128_RATE;
            adlen -= ASCON_128_RATE;
        }
    }

    s.x[0] ^= LOADBYTES(ad, ASCON_128_RATE);
    s.x[0] ^= SETBYTE(0x80, adlen);   // remaining padding bytes
    P6(&s);
    s.x[4] ^= 1;   // padding

    /* process plain text */
    while (mlen >= ASCON_128_RATE) {
        s.x[0] ^= LOADBYTES(m, ASCON_128_RATE);
        STOREBYTES(c, s.x[0], ASCON_128_RATE);
        P6(&s);
        m += ASCON_128_RATE;
        mlen -= ASCON_128_RATE;
        c += ASCON_128_RATE;
    }

    s.x[0] ^= LOADBYTES(m, mlen);
    STOREBYTES(c, s.x[0], mlen);
    s.x[0] ^= SETBYTE(0x80, mlen);   // remaining padding bytes
    c += mlen;

    /* finalization */
    s.x[1] ^= K0;
    s.x[2] ^= K1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    /* set tag */
    STOREBYTES(c, s.x[3], 8);
    STOREBYTES(c + 8, s.x[4], 8);

    return 0;
}