#include "../lib/Unity/unity.h"
#include "../ref/crypto_aead.h"
#include "../src/asconv.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char *ciphertext;
unsigned long long clen;

const unsigned char key[] = "0123456789abcedef";
const unsigned char nonce[] = "0123456789abcedef";
const unsigned char msg[] = "0123456789abcedef";
const unsigned char ad[] = "0123456789abcedef";
unsigned long long mlen = sizeof(msg);
unsigned long long adlen = sizeof(ad);

void init_buffer(unsigned char *buffer, unsigned long long numbytes) {
    unsigned long long i;
    for (i = 0; i < numbytes; i++)
        buffer[i] = (unsigned char) i;
}

void printstate(ascon_state_t s) {
    TEST_PRINTF("\n");
    TEST_PRINTF("ascon state:");
    TEST_PRINTF("  x0: %llx", s.x[0]);
    TEST_PRINTF("  x1: %llx", s.x[1]);
    TEST_PRINTF("  x2: %llx", s.x[2]);
    TEST_PRINTF("  x3: %llx", s.x[3]);
    TEST_PRINTF("  x4: %llx", s.x[4]);
    TEST_PRINTF("\n");
}

void setUp() {}

void tearDown() {}

void test_SETBYTE_ShouldSetByte() {
    uint64_t x = 0x0;
    x |= SETBYTE(0x12, 0);
    x |= SETBYTE(0x12, 7);
    TEST_ASSERT_EQUAL_HEX64(0x1200000000000012, x);
}

void test_ROR_ShouldRotateBits() {
    const uint64_t x = 0x0123456789abcdef;
    const uint64_t y = ROR(x, 1);
    TEST_ASSERT_EQUAL_HEX64(0x8091a2b3c4d5e6f7, y);
}

void test_ROUND_ShouldPermutateBits() {
    ascon_state_t s;
    s.x[0] = ASCON_128_IV;
    s.x[1] = 0xd0596220216b33a1;
    s.x[2] = 0xda2293601952f632;
    s.x[3] = 0x194a547c66378d8c;
    s.x[4] = 0x2fb1704cbcacb37b;
    ROUND(&s, 0x96);

    TEST_ASSERT_EQUAL_HEX64(0xbc4543f2540bb743, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0x6d59713871923bf3, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0x1de36d5a0d9434ef, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x3dd6a301d1a1221d, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0x80532c43c1dcf798, s.x[4]);
}

void test_P6_ShouldPermutateBits() {
    ascon_state_t s;
    s.x[0] = ASCON_128_IV;
    s.x[1] = 0xd0596220216b33a1;
    s.x[2] = 0xda2293601952f632;
    s.x[3] = 0x194a547c66378d8c;
    s.x[4] = 0x2fb1704cbcacb37b;
    P6(&s);

    TEST_ASSERT_EQUAL_HEX64(0x0CEA797C561842E2, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0xE8D53F4EA9555640, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0xAAA882B940CC2E0E, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x600B8DE9CA82F78E, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0x78E11BF87516AC82, s.x[4]);
}

void test_P12_ShouldPermutateBits() {
    ascon_state_t s;
    s.x[0] = ASCON_128_IV;
    s.x[1] = 0xd0596220216b33a1;
    s.x[2] = 0xda2293601952f632;
    s.x[3] = 0x194a547c66378d8c;
    s.x[4] = 0x2fb1704cbcacb37b;
    P12(&s);

    TEST_ASSERT_EQUAL_HEX64(0x194CEEA51869AD84, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0x3376582265C13EC4, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0x2A081DA993B9AF95, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x2F1500A133DBDD82, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0xE8F664254036C3C7, s.x[4]);
}

void test_ascon128_encrypt() {
    unsigned char *ct_ref;
    unsigned char *ct_asconv;
    unsigned long long *clen_ref;
    unsigned long long *clen_asconv;

    ct_ref = malloc(mlen + adlen);
    clen_ref = malloc(sizeof(unsigned long long));
    ct_asconv = malloc(mlen + adlen);
    clen_asconv = malloc(sizeof(unsigned long long));

    int encrypted_ref_result = crypto_aead_encrypt(ct_ref, clen_ref, msg, mlen,
                                                   ad, adlen, NULL, nonce, key);

    int encrypted_asconv_result = ascon128_encrypt(ct_asconv, clen_asconv, msg,
                                                   mlen, ad, adlen, key, nonce);

    TEST_ASSERT_EQUAL_INT(0, encrypted_ref_result);
    TEST_ASSERT_EQUAL_INT(0, encrypted_asconv_result);
    TEST_ASSERT_EQUAL_UINT64(*clen_ref, *clen_asconv);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ct_ref, ct_asconv, *clen_ref);

    /* malloc and copy cyphertext to global variable */
    ciphertext = malloc(*clen_asconv);
    memcpy(ciphertext, ct_asconv, *clen_asconv);
    clen = *clen_asconv;

    free(ct_ref);
    free(ct_asconv);
    free(clen_ref);
    free(clen_asconv);
}

void test_ascon128_decrypt() {

    unsigned char *msg_ref;
    unsigned char *msg_asconv;
    unsigned long long *mlen_ref;
    unsigned long long *mlen_asconv;

    msg_ref = malloc(mlen + adlen);
    msg_asconv = malloc(mlen + adlen);
    mlen_ref = malloc(sizeof(unsigned long long));
    mlen_asconv = malloc(sizeof(unsigned long long));

    int decryption_ref_result = crypto_aead_decrypt(
        msg_ref, mlen_ref, NULL, ciphertext, clen, ad, adlen, nonce, key);

    int decryption_asconv_result = ascon128_decrypt(
        msg_asconv, mlen_asconv, ciphertext, clen, ad, adlen, key, nonce);

    TEST_ASSERT_EQUAL_INT(0, decryption_ref_result);
    TEST_ASSERT_EQUAL_INT(0, decryption_asconv_result);
    TEST_ASSERT_EQUAL_UINT64(*mlen_ref, *mlen_asconv);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(msg_ref, msg_asconv, *mlen_asconv);
    TEST_ASSERT_EQUAL_STRING(msg, msg_asconv);

    free(msg_ref);
    free(msg_asconv);
    free(mlen_ref);
    free(mlen_asconv);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_SETBYTE_ShouldSetByte);
    RUN_TEST(test_ROR_ShouldRotateBits);
    RUN_TEST(test_ROUND_ShouldPermutateBits);
    RUN_TEST(test_P6_ShouldPermutateBits);
    RUN_TEST(test_P12_ShouldPermutateBits);
    RUN_TEST(test_ascon128_encrypt);
    RUN_TEST(test_ascon128_decrypt);

    return UNITY_END();
}