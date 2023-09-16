#include "../lib/Unity/unity.h"
#include "../src/asconv.h"
#include <assert.h>
#include <stdio.h>

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

void setUp(void) {}

void tearDown(void) {}

void test_ROR_ShouldRotateBits() {
    uint64_t x = 0x0123456789abcdef;
    uint64_t y = ROR(x, 1);
    TEST_ASSERT_EQUAL_HEX64(0x8091a2b3c4d5e6f7, y);
}

void test_ROUND_ShouldPermutateBits(void) {
    ascon_state_t s;
    s.x[0] = ASCON_128_IV;
    s.x[1] = 0xd0596220216b33a1;
    s.x[2] = 0xda2293601952f632;
    s.x[3] = 0x194a547c66378d8c;
    s.x[4] = 0x2fb1704cbcacb37b;
    ROUND(&s, 0x96);
    printstate(s);

    TEST_ASSERT_EQUAL_HEX64(0xbc4543f2540bb743, s.x[0]);
    TEST_ASSERT_EQUAL_HEX64(0x6d59713871923bf3, s.x[1]);
    TEST_ASSERT_EQUAL_HEX64(0x1de36d5a0d9434ef, s.x[2]);
    TEST_ASSERT_EQUAL_HEX64(0x3dd6a301d1a1221d, s.x[3]);
    TEST_ASSERT_EQUAL_HEX64(0x80532c43c1dcf798, s.x[4]);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_ROR_ShouldRotateBits);
    RUN_TEST(test_ROUND_ShouldPermutateBits);
    return UNITY_END();
}