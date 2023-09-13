#include <stdint.h>

typedef struct {
    uint64_t x[5];
} ascon_state_t;

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