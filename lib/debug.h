static inline unsigned long long rdtime() {
    unsigned long long cycle;
    asm volatile("rdtime %0" : "=r"(cycle));
    return cycle;
}