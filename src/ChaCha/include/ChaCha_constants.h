#ifndef LIBCRYPTO_CHACHA_CONSTANTS_H
#define LIBCRYPTO_CHACHA_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define CHACHA_NONCE_LENGTH 3
#define CHACHA_COUNTER_LENGTH 1

typedef enum ChaCha_Block_Length_t {
    ChaCha_Block_512 = ((512 / __CHAR_BIT__) / sizeof(uint32_t))

} ChaCha_Block_Length_t;

typedef enum ChaCha_Key_Length_t {
    ChaCha_Key_256 = ((256 / __CHAR_BIT__) / sizeof(uint32_t))

} ChaCha_Key_Length_t;

/*
    ChaCha_Round_Count_t

    This defines the number of rounds done by the given ChaCha implementation.
    This is half the number to actually perform, as the algorithm is composed of
    "even" and "odd" rounds, which are distinct.
*/
typedef enum ChaCha_Round_Count_t {
    ChaCha_Round_20 = 10

} ChaCha_Round_Count_t;

extern const uint8_t ChaChaConstant[16];

#ifdef __cplusplus
}
#endif

#endif
