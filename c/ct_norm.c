// aethel-core/c/ct_norm.c — Constant-Time Norm Verification for Enclave

#include <stdint.h>
#define RING_N 256
#define MODULE_K 4

// Constant-time norm checking across all coefficients
uint32_t ct_check_norm_bound(const int32_t z[MODULE_K][RING_N], int32_t bound) {
    uint32_t bad_coeff_mask = 0;
    for (size_t i = 0; i < MODULE_K; i++) {
        for (size_t j = 0; j < RING_N; j++) {
            int32_t coeff = z[i][j];
            // Compute absolute value in constant time
            int32_t mask = coeff >> 31;
            int32_t abs_coeff = (coeff + mask) ^ mask;
            // Accumulate bitwise OR mask if abs_coeff >= bound
            int32_t diff = (bound - 1) - abs_coeff;
            bad_coeff_mask |= (uint32_t)(diff >> 31);
        }
    }
    // Returns 0 if all coefficients are within bounds, 0xFFFFFFFF if rejected
    return bad_coeff_mask;
}

// Force compiler execution of memory sanitization
void enclave_explicit_zeroize(volatile void *v, size_t n) {
    volatile char *p = (volatile char *)v;
    while (n--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}
