#include "asconv.h"

int ascon128_encrypt(unsigned char *c, unsigned long long *clen,
                     const unsigned char *m, unsigned long long mlen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k, const unsigned char *n) {
    ascon_state_t s;
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    const uint64_t N0 = LOADBYTES(n, 8);
    const uint64_t N1 = LOADBYTES(n + 8, 8);

    /* set ciphertext size */
    *clen = mlen + CRYPTO_ABYTES;

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
        s.x[0] ^= LOADBYTES(ad, adlen);
        s.x[0] ^= PAD(adlen);   // remaining padding bytes
        P6(&s);
    }

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
    s.x[0] ^= PAD(mlen);   // remaining padding bytes
    c += mlen;

    /* finalization */
    s.x[1] ^= K0;
    s.x[2] ^= K1;
    P12(&s);

    /* set tag */
    s.x[3] ^= K0;
    s.x[4] ^= K1;
    STOREBYTES(c, s.x[3], 8);
    STOREBYTES(c + 8, s.x[4], 8);

    return 0;
}

int ascon128_decrypt(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *c, unsigned long long clen,
                     const unsigned char *ad, unsigned long long adlen,
                     const unsigned char *k, const unsigned char *n) {
    ascon_state_t s;
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    const uint64_t N0 = LOADBYTES(n, 8);
    const uint64_t N1 = LOADBYTES(n + 8, 8);
    uint64_t ci;

    if (clen < CRYPTO_ABYTES)
        return -1;

    /* set plaintext size */
    *mlen = clen - CRYPTO_ABYTES;

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
        /* final associated data block */
        s.x[0] ^= LOADBYTES(ad, adlen);
        s.x[0] ^= PAD(adlen);
        P6(&s);
    }
    s.x[4] ^= 1;

    /* process ciphertext */
    clen -= CRYPTO_ABYTES;
    while (clen >= ASCON_128_RATE) {
        ci = LOADBYTES(c, ASCON_128_RATE);
        s.x[0] ^= ci;
        STOREBYTES(m, s.x[0], ASCON_128_RATE);
        s.x[0] = ci;
        P6(&s);
        m += ASCON_128_RATE;
        c += ASCON_128_RATE;
        clen -= ASCON_128_RATE;
    }

    ci = LOADBYTES(c, clen);
    STOREBYTES(m, s.x[0] ^ ci, clen);
    c += clen;

    uint64_t r = (s.x[0] ^ ci) >> ((ASCON_128_RATE - clen) * 8)
                                      << ((ASCON_128_RATE - clen) * 8) |
                 PAD(clen);
    s.x[0] ^= r;

    /* finalization */
    s.x[1] ^= K0;
    s.x[2] ^= K1;
    P12(&s);

    /* set tag */
    uint8_t t[CRYPTO_ABYTES];
    s.x[3] ^= K0;
    s.x[4] ^= K1;
    STOREBYTES(t, s.x[3], 8);
    STOREBYTES(t + 8, s.x[4], 8);

    int16_t result = 0;
    for (uint8_t i = 0; i < CRYPTO_ABYTES; i++)
        result |= c[i] ^ t[i];
    result = (((result - 1) >> 8) & 1) - 1;   // 0 if equal, -1 otherwise

    return result;
}
