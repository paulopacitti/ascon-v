#include "../opt64/crypto_aead.h"
#include "../ref/crypto_aead.h"
#include "../src/asconv.h"
#include <stdio.h>
#include <stdlib.h>

#define REFERENCE_IMPLEMENTATION 0
#define OPT64_IMPLEMENTATION     1
#define ASCONV_IMPLEMENTATION    2

const int ITERATIONS = 2000;
const int RESOLUTION = 45;   // 45 ns on T-Head C906;
const double NS = 0.000000001;
const unsigned long long FREQUENCY = 1000000000;

unsigned char key[16];
unsigned char nonce[16];
unsigned char *ad;
unsigned char *ct;
unsigned char *msg;
unsigned char *decrypted_msg;
unsigned long long decrypted_mlen;
unsigned long long mlen = 1000;
unsigned long long adlen = 16;
unsigned long long clen;
int result = 0;

static inline uint64_t rdtime() {
    uint64_t cycle;
    asm volatile("rdtime %0" : "=r"(cycle));
    return cycle;
}

static inline void init_buffer(unsigned char *buffer,
                               unsigned long long numbytes) {
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

unsigned clock_count(unsigned long long time_ns) {
    return (unsigned int) (((time_ns * NS) / 60) * FREQUENCY);
}

void benchmark_init(unsigned long long message_length,
                    unsigned long long ad_length) {
    mlen = message_length;
    adlen = ad_length;
    msg = realloc(msg, mlen * sizeof(unsigned char));
    ad = realloc(ad, adlen * sizeof(unsigned char));
    ct = realloc(ct, (mlen + adlen) * sizeof(unsigned char));
    decrypted_msg = realloc(decrypted_msg, (mlen) * sizeof(unsigned char));

    init_buffer(key, sizeof(key));
    init_buffer(nonce, sizeof(nonce));
    init_buffer(msg, mlen);
    init_buffer(ad, adlen);
}

void benchmark_encryption(int method, unsigned long long *time,
                          unsigned int *cycles) {
    unsigned long long ref_timer_start;
    unsigned long long ref_timer_end;
    unsigned long long time_counts[ITERATIONS];
    unsigned long long time_elapsed;

    switch (method) {
    case REFERENCE_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            crypto_aead_encrypt(ct, &clen, msg, mlen, ad, adlen, (void *) 0,
                                nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }

        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;

    case OPT64_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            crypto_aead_encrypt_opt64(ct, &clen, msg, mlen, ad, adlen,
                                      (void *) 0, nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }

        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case ASCONV_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            result |=
                ascon128_encrypt(ct, &clen, msg, mlen, ad, adlen, key, nonce);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        return;
    }
}

void benchmark_decryption(int method, unsigned long long *time,
                          unsigned int *cycles) {
    unsigned long long ref_timer_start;
    unsigned long long ref_timer_end;
    unsigned long long time_counts[ITERATIONS];
    unsigned long long time_elapsed;

    switch (method) {
    case REFERENCE_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            result |= crypto_aead_decrypt(decrypted_msg, &decrypted_mlen, NULL,
                                          ct, clen, ad, adlen, nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case OPT64_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            result |=
                crypto_aead_decrypt_opt64(decrypted_msg, &decrypted_mlen, NULL,
                                          ct, clen, ad, adlen, nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case ASCONV_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            result |= ascon128_decrypt(decrypted_msg, &decrypted_mlen, ct, clen,
                                       ad, adlen, key, nonce);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = average_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        return;
    }
}

int main() {
    int message_sizes[5] = {8, 32, 64, 1000, 4000};
    unsigned long long encryption_ref_time_ns[5];
    unsigned int encryption_ref_cycles[5];
    unsigned long long encryption_opt64_time_ns[5];
    unsigned int encryption_opt64_cycles[5];
    unsigned long long encryption_asconv_time_ns[5];
    unsigned int encryption_asconv_cycles[5];

    unsigned long long decryption_ref_time_ns[5];
    unsigned int decryption_ref_cycles[5];
    unsigned long long decryption_opt64_time_ns[5];
    unsigned int decryption_opt64_cycles[5];
    unsigned long long decryption_asconv_time_ns[5];
    unsigned int decryption_asconv_cycles[5];

    msg = malloc(sizeof(unsigned char));
    ad = malloc(sizeof(unsigned char));
    ct = malloc(sizeof(unsigned char));
    decrypted_msg = malloc(sizeof(unsigned char));

    for (int i = 0; i < 5; i++) {
        benchmark_init(message_sizes[i], 16);
        benchmark_encryption(REFERENCE_IMPLEMENTATION,
                             &encryption_ref_time_ns[i],
                             &encryption_ref_cycles[i]);
        benchmark_encryption(OPT64_IMPLEMENTATION, &encryption_opt64_time_ns[i],
                             &encryption_opt64_cycles[i]);
        benchmark_encryption(ASCONV_IMPLEMENTATION,
                             &encryption_asconv_time_ns[i],
                             &encryption_asconv_cycles[i]);
        benchmark_decryption(REFERENCE_IMPLEMENTATION,
                             &decryption_ref_time_ns[i],
                             &decryption_ref_cycles[i]);
        benchmark_decryption(OPT64_IMPLEMENTATION, &decryption_opt64_time_ns[i],
                             &decryption_opt64_cycles[i]);
        benchmark_decryption(ASCONV_IMPLEMENTATION,
                             &decryption_asconv_time_ns[i],
                             &decryption_asconv_cycles[i]);
    }

    /* Performance table */
    printf("Performance table:\n");
    printf("___________________________________________________________________"
           "__________________________________\n");
    printf("%-15s%-20s%-12s%-18s%-10s%-15s%-10s\n", "[Algorithm]",
           "[Message size (B)]", "[Operation]", "[Implementation]", "[Cycles]",
           "[Cycles/B]", "[Time (s)]");
    for (int i = 0; i < 4; i++) {
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "encryption", "reference",
               encryption_ref_cycles[i],
               encryption_ref_cycles[i] / message_sizes[i],
               encryption_ref_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "encryption", "opt64",
               encryption_opt64_cycles[i],
               encryption_opt64_cycles[i] / message_sizes[i],
               encryption_opt64_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "encryption", "asconv",
               encryption_asconv_cycles[i],
               encryption_asconv_cycles[i] / message_sizes[i],
               encryption_asconv_time_ns[i] * NS);

        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "reference",
               decryption_ref_cycles[i],
               decryption_ref_cycles[i] / message_sizes[i],
               decryption_ref_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "opt64",
               decryption_opt64_cycles[i],
               decryption_opt64_cycles[i] / message_sizes[i],
               decryption_opt64_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "asconv",
               decryption_opt64_cycles[i],
               decryption_asconv_cycles[i] / message_sizes[i],
               decryption_asconv_time_ns[i] * NS);
    }
    printf("___________________________________________________________________"
           "__________________________________\n");

    /* Speedup results */
    printf("Speedup results (with a message size of 4MB):\n");
    printf("%-20s%-30s%-30s%-30s%-30s\n", "[Implementation]",
           "[Encryption (clock cycles)]", "[Decryption (clock cycles)]",
           "[Encryption relative speed]", "[Decryption relative speed]");
    printf("%-20s%-30d%-30d%-30.2f%-30.2f\n", "reference",
           encryption_ref_cycles[4], decryption_ref_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_ref_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_ref_cycles[4]));
    printf("%-20s%-30d%-30d%-30.2f%-30.2f\n", "opt64",
           encryption_opt64_cycles[4], decryption_opt64_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_opt64_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_opt64_cycles[4]));
    printf("%-20s%-30d%-30d%-30.2f%-30.2f\n", "asconv",
           encryption_asconv_cycles[4], decryption_asconv_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_asconv_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_asconv_cycles[4]));

    free(ct);
    free(ad);
    free(msg);

    return 0;
}
