#include <stdint.h>

#include "include/cipher.h"

void BlockXOR(uint8_t *A, const uint8_t *B, size_t Length) {

    size_t Index;

    for (Index = 0; Index < Length; Index++) {
        A[Index] ^= B[Index];
    }

    return;
}
