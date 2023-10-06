#include "../ref/crypto_aead.h"
#include "../src/asconv.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

const int ITERATIONS = 128;

void init_buffer(unsigned char *buffer, unsigned long long numbytes) {
    unsigned long long i;
    for (i = 0; i < numbytes; i++)
        buffer[i] = (unsigned char) i;
}

int average_clock_count(unsigned long *clock_counts, int num_clocks) {
    unsigned long long sum = 0;
    for (int i = 0; i < num_clocks; i++) {
        sum += clock_counts[i];
    }
    return sum / num_clocks;
}

int main() {
    unsigned long ref_clock_start;
    unsigned long ref_clock_end;
    int avg_clock_count;
    unsigned long clock_counts[ITERATIONS];

    unsigned char key[128];
    unsigned char nonce[128];
    unsigned char *ad;
    unsigned char *ct;
    unsigned char *msg;
    unsigned long long mlen = 4096;
    unsigned long long adlen = 16;
    unsigned long long clen;
    int result = 0;

    msg = malloc(mlen);
    ad = malloc(adlen);
    ct = malloc(mlen + adlen);

    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));

    for (int i = 0; i < ITERATIONS; i++) {
        ref_clock_start = clock();
        result |= crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen,
                                      (void *) 0, nonce, key);
        ref_clock_end = clock();
        clock_counts[i] = ref_clock_end - ref_clock_start;
    }

    avg_clock_count = average_clock_count(clock_counts, ITERATIONS);
    printf("======= REFERENCE IMPLEMENTATION =======\n");
    printf("ascon128v12 encrypt():\n");
    printf("    clock cycles: %d\n", avg_clock_count);
    printf("    time: %.8lf\n", (double) avg_clock_count / CLOCKS_PER_SEC);
    return 0;
}
