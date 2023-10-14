#include "../ref/crypto_aead.h"
#include "../src/asconv.h"
#include <stdio.h>
#include <stdlib.h>

const int ITERATIONS = 1024;
const int RESOLUTION = 45;   // 45 ns on T-Head C906;
const double NS = 0.000000001;
const unsigned long long FREQUENCY = 1000000000;

static inline uint64_t rdtime() {
    uint64_t cycle;
    asm volatile("rdtime %0" : "=r"(cycle));
    return cycle;
}

void init_buffer(unsigned char *buffer, unsigned long long numbytes) {
    unsigned long long i;
    for (i = 0; i < numbytes; i++)
        buffer[i] = (unsigned char) i;
}

unsigned long long average_time_elapsed(unsigned long long *time_counts,
                                        int len) {
    unsigned long long sum = 0;
    for (int i = 0; i < len; i++) {
        sum += time_counts[i];
    }
    return (sum / len) * RESOLUTION;
}

int main() {
    unsigned long long ref_timer_start;
    unsigned long long ref_timer_end;
    unsigned long long avg_time_count;
    unsigned long long time_counts[ITERATIONS];

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
        ref_timer_start = rdtime();
        result |= crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen,
                                      (void *) 0, nonce, key);
        ref_timer_end = rdtime();
        time_counts[i] = ref_timer_end - ref_timer_start;
    }

    avg_time_count = average_time_elapsed(time_counts, ITERATIONS);
    printf("======= REFERENCE IMPLEMENTATION =======\n");
    printf("ascon128v12 encrypt():\n");
    printf("    clock cycles: %d\n",
           (unsigned int) (((avg_time_count * NS) / 60) * FREQUENCY));
    printf("    time: %.9f\n", avg_time_count * NS);

    for (int i = 0; i < ITERATIONS; i++) {
        ref_timer_start = rdtime();
        result |= ascon128_encrypt(ct, &clen, msg, mlen, ad, adlen, key, nonce);
        ref_timer_end = rdtime();
        time_counts[i] = ref_timer_end - ref_timer_start;
    }

    avg_time_count = average_time_elapsed(time_counts, ITERATIONS);
    printf("======= ASCON-V IMPLEMENTATION =======\n");
    printf("ascon128v12 encrypt():\n");
    printf("    clock cycles: %d\n",
           (unsigned int) (((avg_time_count * NS) / 60) * FREQUENCY));
    printf("    time: %.9f\n", avg_time_count * NS);
    return 0;
}
