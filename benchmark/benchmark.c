#include "../lib/debug.h"
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

int uint64_cmp(const void *a, const void *b) {
    unsigned long long *x = (unsigned long long *) a;
    unsigned long long *y = (unsigned long long *) b;
    return (int) (*x - *y);
}

int my_ceil(double num) {
    int inum = (int) num;
    if (num == (float) inum) {
        return inum;
    }
    return inum + 1;
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

unsigned long long median_time_elapsed(unsigned long long *time_counts,
                                       int len) {
    qsort(time_counts, len, sizeof(unsigned long long), uint64_cmp);
    return time_counts[len / 2] * RESOLUTION;
}

unsigned int clock_count(unsigned long long time_ns) {
    return (unsigned int) my_ceil((((double) (time_ns * NS)) / 60) * FREQUENCY);
}

void benchmark_restart(unsigned long long message_length,
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

        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
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

        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case ASCONV_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            ascon128_encrypt(ct, &clen, msg, mlen, ad, adlen, key, nonce);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
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
            crypto_aead_decrypt(decrypted_msg, &decrypted_mlen, NULL, ct, clen,
                                ad, adlen, nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case OPT64_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            crypto_aead_decrypt_opt64(decrypted_msg, &decrypted_mlen, NULL, ct,
                                      clen, ad, adlen, nonce, key);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);

        return;
    case ASCONV_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ref_timer_start = rdtime();
            ascon128_decrypt(decrypted_msg, &decrypted_mlen, ct, clen, ad,
                             adlen, key, nonce);
            ref_timer_end = rdtime();
            time_counts[i] = ref_timer_end - ref_timer_start;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        return;
    }
}

void benchmark_decryption_final_ciphertext_stage(int method,
                                                 unsigned long long *time,
                                                 unsigned int *cycles) {
    unsigned long long time_counts[ITERATIONS];
    unsigned long long time_elapsed;
    unsigned long long timer;

    switch (method) {
    case REFERENCE_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            crypto_aead_decrypt_debug(decrypted_msg, &decrypted_mlen, NULL, ct,
                                      clen, ad, adlen, nonce, key, &timer);
            time_counts[i] = timer;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        // printf("cycles: %u\n", *cycles);
        // printf("time: %llu\n", *time);

        return;
    case OPT64_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            crypto_aead_decrypt_opt64_debug(decrypted_msg, &decrypted_mlen,
                                            NULL, ct, clen, ad, adlen, nonce,
                                            key, &timer);
            time_counts[i] = timer;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        // printf("cycles: %u\n", *cycles);
        // printf("time: %llu\n", *time);

        return;
    case ASCONV_IMPLEMENTATION:
        for (int i = 0; i < ITERATIONS; i++) {
            ascon128_decrypt_debug(decrypted_msg, &decrypted_mlen, ct, clen, ad,
                                   adlen, key, nonce, &timer);
            time_counts[i] = timer;
        }
        time_elapsed = median_time_elapsed(time_counts, ITERATIONS);
        *time = time_elapsed;
        *cycles = clock_count(time_elapsed);
        // printf("cycles: %u\n", *cycles);
        // printf("time: %llu\n", *time);

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
    unsigned long long decryption_ref_final_ciphertext_stage_ns[5];
    unsigned int decryption_ref_final_ciphertext_stage_cycles[5];

    unsigned long long decryption_opt64_time_ns[5];
    unsigned int decryption_opt64_cycles[5];
    unsigned long long decryption_opt64_final_ciphertext_stage_ns[5];
    unsigned int decryption_opt64_final_ciphertext_stage_cycles[5];

    unsigned long long decryption_asconv_time_ns[5];
    unsigned int decryption_asconv_cycles[5];
    unsigned long long decryption_asconv_final_ciphertext_stage_ns[5];
    unsigned int decryption_asconv_final_ciphertext_stage_cycles[5];

    msg = malloc(sizeof(unsigned char));
    ad = malloc(sizeof(unsigned char));
    ct = malloc(sizeof(unsigned char));
    decrypted_msg = malloc(sizeof(unsigned char));

    for (int i = 0; i < 5; i++) {
        // ref implementation
        benchmark_restart(message_sizes[i], 16);
        benchmark_encryption(REFERENCE_IMPLEMENTATION,
                             &encryption_ref_time_ns[i],
                             &encryption_ref_cycles[i]);
        benchmark_decryption(REFERENCE_IMPLEMENTATION,
                             &decryption_ref_time_ns[i],
                             &decryption_ref_cycles[i]);
        benchmark_decryption_final_ciphertext_stage(
            REFERENCE_IMPLEMENTATION, decryption_ref_final_ciphertext_stage_ns,
            decryption_ref_final_ciphertext_stage_cycles);

        // opt64 implementation
        benchmark_restart(message_sizes[i], 16);
        benchmark_encryption(OPT64_IMPLEMENTATION, &encryption_opt64_time_ns[i],
                             &encryption_opt64_cycles[i]);
        benchmark_decryption(OPT64_IMPLEMENTATION, &decryption_opt64_time_ns[i],
                             &decryption_opt64_cycles[i]);
        benchmark_decryption_final_ciphertext_stage(
            OPT64_IMPLEMENTATION, decryption_opt64_final_ciphertext_stage_ns,
            decryption_opt64_final_ciphertext_stage_cycles);

        // asconv implementation
        benchmark_restart(message_sizes[i], 16);
        benchmark_encryption(ASCONV_IMPLEMENTATION,
                             &encryption_asconv_time_ns[i],
                             &encryption_asconv_cycles[i]);
        benchmark_decryption(ASCONV_IMPLEMENTATION,
                             &decryption_asconv_time_ns[i],
                             &decryption_asconv_cycles[i]);
        benchmark_decryption_final_ciphertext_stage(
            ASCONV_IMPLEMENTATION, decryption_asconv_final_ciphertext_stage_ns,
            decryption_asconv_final_ciphertext_stage_cycles);
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
               ((int) my_ceil(((double) encryption_ref_cycles[i] /
                               (double) message_sizes[i]))),
               encryption_ref_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "encryption", "opt64",
               encryption_opt64_cycles[i],
               ((int) my_ceil(((double) encryption_opt64_cycles[i] /
                               (double) message_sizes[i]))),
               encryption_opt64_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "encryption", "asconv",
               encryption_asconv_cycles[i],
               ((int) my_ceil(((double) encryption_asconv_cycles[i] /
                               (double) message_sizes[i]))),
               encryption_asconv_time_ns[i] * NS);

        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "reference",
               decryption_ref_cycles[i],
               ((int) my_ceil(((double) decryption_ref_cycles[i] /
                               (double) message_sizes[i]))),
               decryption_ref_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "opt64",
               decryption_opt64_cycles[i],
               ((int) my_ceil(((double) decryption_opt64_cycles[i] /
                               (double) message_sizes[i]))),
               decryption_opt64_time_ns[i] * NS);
        printf("%-15s%-20d%-12s%-18s%-10u%-15u%-10.9f\n", "Ascon128",
               message_sizes[i], "decryption", "asconv",
               decryption_asconv_cycles[i],
               ((int) my_ceil(((double) decryption_asconv_cycles[i] /
                               (double) message_sizes[i]))),
               decryption_asconv_time_ns[i] * NS);
    }
    printf("___________________________________________________________________"
           "__________________________________\n");

    /* Speedup results */
    printf("Speedup results (with a message size of 4MB):\n");
    printf("___________________________________________________________________"
           "__________________________________\n");

    printf("%-20s%-20s%-20s%-20s%-20s\n", "[Implementation]",
           "[Encrypt (cycles)]", "[Decrypt (cycles)]", "[Encrypt (speed)]",
           "[Decrypt (speed)]");
    printf("%-20s%-20d%-20d%-20.2f%-20.2f\n", "reference",
           encryption_ref_cycles[4], decryption_ref_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_ref_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_ref_cycles[4]));
    printf("%-20s%-20d%-20d%-20.2f%-20.2f\n", "opt64",
           encryption_opt64_cycles[4], decryption_opt64_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_opt64_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_opt64_cycles[4]));
    printf("%-20s%-20d%-20d%-20.2f%-20.2f\n", "asconv",
           encryption_asconv_cycles[4], decryption_asconv_cycles[4],
           (float) ((float) encryption_ref_cycles[4] /
                    (float) encryption_asconv_cycles[4]),
           (float) ((float) decryption_ref_cycles[4] /
                    (float) decryption_asconv_cycles[4]));
    printf("___________________________________________________________________"
           "__________________________________\n");

    printf("Final ciphertext stage operation comperison (with a message size "
           "of 4MB):\n");
    printf("___________________________________________________________________"
           "__________________________________\n");

    printf("%-20s%-20s%-20s%-20s\n", "[Implementation]", "[Decrypt (cycles)]",
           "[Decrypt (time)]", "[Decrypt (speed)]");
    printf("%-20s%-20u%-20.9f%-20.2f\n", "reference",
           decryption_ref_final_ciphertext_stage_cycles[4],
           decryption_ref_final_ciphertext_stage_ns[4] * NS,
           (float) ((float) decryption_ref_final_ciphertext_stage_cycles[4] /
                    (float) decryption_ref_final_ciphertext_stage_cycles[4]));
    printf("%-20s%-20u%-20.9f%-20.2f\n", "opt64",
           decryption_opt64_final_ciphertext_stage_cycles[4],
           decryption_opt64_final_ciphertext_stage_ns[4] * NS,
           (float) ((float) decryption_ref_final_ciphertext_stage_cycles[4] /
                    (float) decryption_opt64_final_ciphertext_stage_cycles[4]));
    printf(
        "%-20s%-20u%-20.9f%-20.2f\n", "asconv",
        decryption_asconv_final_ciphertext_stage_cycles[4],
        decryption_asconv_final_ciphertext_stage_ns[4] * NS,
        (float) ((float) decryption_ref_final_ciphertext_stage_cycles[4] /
                 (float) decryption_asconv_final_ciphertext_stage_cycles[4]));

    printf("___________________________________________________________________"
           "__________________________________\n");

    free(ct);
    free(ad);
    free(msg);

    return 0;
}
