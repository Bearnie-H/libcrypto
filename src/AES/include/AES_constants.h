#ifndef LIBCRYPTO_AES_CONSTANTS_H
#define LIBCRYPTO_AES_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

extern const uint8_t S_Box[256];

extern const uint8_t Inv_S_Box[256];

extern const uint8_t RoundConstants[11];

/*
    AES_Block_Length_t

    This enum is defined to provide an additional level of type-safety
    for setting the corresponding field of the AES_Context_t field.

    The AES Block size is fixed at 128 bits in length, but this is
    parameterized to remove "magic numbers" from the algorithm, and
    on the rare chance AES is ever expanded to allow for multiple block
    sizes.

    The named value is set such that it corresponds to the number
    of 32-bit words in the block.
*/
typedef enum AES_Block_Length_t {
    AES_Block_128 = 4

} AES_Block_Length_t;

/*
    AES_Key_Length_t

    This enum is defined to provide an additional level of type-safety
    for setting the corresponding field of the AES_Context_t field.

    The values assigned to the named elements is such that each value
    corresponds to the number of 32-bit words in the key.
*/
typedef enum AES_Key_Length_t {
    AES_Key_128 = 4,
    AES_Key_192 = 6,
    AES_Key_256 = 8

} AES_Key_Length_t;

/*
    AES_Round_Count_t

    This enum is defined to provide an additional level of type-safety
    for setting the corresponding field of the AES_Context_t field.

    The values assigned to the named elements is such that the name
    corresponds to the number of rounds to perform.
*/
typedef enum AES_Round_Count_t {
    AES_Round_10 = 10,
    AES_Round_12 = 12,
    AES_Round_14 = 14

} AES_Round_Count_t;

#ifdef __cplusplus
}
#endif

#endif
