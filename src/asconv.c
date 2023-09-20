#include "asconv.h"

uint64_t LOADBYTES(const uint8_t *bytes, uint8_t n) {
    int i;   // max key lenght is 128 bits
    uint64_t x = 0;
    for (i = 0; i < n; ++i)
        x |= SETBYTE(bytes[i], i);
    return x;
}

uint64_t SETBYTE(const uint8_t b, int i) {
    return ((uint64_t) (b) << (56 - 8 * (i)));
}

uint64_t ROR(uint64_t x, int n) { return x >> n | x << (-n & 63); }

void ROUND(ascon_state_t *s, uint8_t C) {
    ascon_state_t t;
    /* addition of round constant */
    s->x[2] ^= C;
    /* substitution layer */
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    /* start of s-box */
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    /* end of s-box */
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