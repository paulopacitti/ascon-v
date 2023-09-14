#include "../lib/Unity/unity.h"
#include "../src/asconv.h"

#include <stdio.h>

void setUp(void) {}

void tearDown(void) {}

void test_ROR_ShouldRotateBits(void) {
    uint64_t x = 0x0123456789abcdef;
    uint64_t y = ROR(x, 1);
    TEST_ASSERT_EQUAL_HEX64(0x8091a2b3c4d5e6f7, y);
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_ROR_ShouldRotateBits);
    return UNITY_END();
}