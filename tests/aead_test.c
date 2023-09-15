// #include "../lib/Unity/unity.h"
#include "../src/asconv.h"
#include <assert.h>
#include <stdio.h>

void printstate(ascon_state_t s) {
    printf("ascon state:\n");
    printf("  x0: %016llx\n", s.x[0]);
    printf("  x1: %016llx\n", s.x[1]);
    printf("  x2: %016llx\n", s.x[2]);
    printf("  x3: %016llx\n", s.x[3]);
    printf("  x4: %016llx\n", s.x[4]);
}

void test_ROR_ShouldRotateBits() {
    uint64_t x = 0x0123456789abcdef;
    uint64_t y = ROR(x, 1);

    assert(0x8091a2b3c4d5e6f7 == y);
}

void test_ROUND_ShouldPermutateBits(void) {
    ascon_state_t s;
    s.x[0] = ASCON_128_IV;
    s.x[1] = 0xd0596220216b33a1;
    s.x[2] = 0xda2293601952f632;
    s.x[3] = 0x194a547c66378d8c;
    s.x[4] = 0x2fb1704cbcacb37b;
    ROUND(&s, 0x96);

    assert(0xbc4543f2540bb743 == s.x[0]);
    assert(0x6d59713871923bf3 == s.x[1]);
    assert(0x1de36d5a0d9434ef == s.x[2]);
    assert(0x3dd6a301d1a1221d == s.x[3]);
    assert(0x80532c43c1dcf798 == s.x[4]);
}

int main() {
    printf("\n=== TESTS ===========================\n");
    test_ROR_ShouldRotateBits();
    printf("test_ROR_ShouldRotateBits passed!\n");
    test_ROUND_ShouldPermutateBits();
    printf("test_ROUND_ShouldPermutateBits passed!\n");
    return 0;
}