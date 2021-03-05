#ifndef LIBCRYPTO_AES_TEST_H
#define LIBCRYPTO_AES_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "AES_constants.h"

/* Vectors for testing the KeyExpansion function */
extern const uint8_t AES_Test_Expansion_Key_128[sizeof(uint32_t) * AES_Key_128];
extern const uint8_t AES_Test_Expansion_Key_192[sizeof(uint32_t) * AES_Key_192];
extern const uint8_t AES_Test_Expansion_Key_256[sizeof(uint32_t) * AES_Key_256];
extern const uint8_t
    AES_Test_Key_128_Expanded[sizeof(uint32_t) * AES_Block_128 * (AES_Round_10 + 1)];
extern const uint8_t
    AES_Test_Key_192_Expanded[sizeof(uint32_t) * AES_Block_128 * (AES_Round_12 + 1)];
extern const uint8_t
    AES_Test_Key_256_Expanded[sizeof(uint32_t) * AES_Block_128 * (AES_Round_14 + 1)];

/*
    Vectors for testing the full block encryption and decryption

    These vectors are such that the decryption input is equal to the encryption output.
*/
extern const uint8_t AES_Test_Key_128[sizeof(uint32_t) * AES_Key_128];
extern const uint8_t AES_Test_Key_192[sizeof(uint32_t) * AES_Key_192];
extern const uint8_t AES_Test_Key_256[sizeof(uint32_t) * AES_Key_256];

extern const uint8_t AES_Test_Enc_InputVector[sizeof(uint32_t) * AES_Block_128];

extern const uint8_t AES_Test_Dec_InputVector_128[sizeof(uint32_t) * AES_Block_128];
extern const uint8_t AES_Test_Dec_InputVector_192[sizeof(uint32_t) * AES_Block_128];
extern const uint8_t AES_Test_Dec_InputVector_256[sizeof(uint32_t) * AES_Block_128];

int Test_AES(void);

int Test_AES_Encrypt_Block(void);
int Test_AES_Encrypt_Block_128(void);
int Test_AES_Encrypt_Block_192(void);
int Test_AES_Encrypt_Block_256(void);

int Test_AES_Decrypt_Block(void);
int Test_AES_Decrypt_Block_128(void);
int Test_AES_Decrypt_Block_192(void);
int Test_AES_Decrypt_Block_256(void);

#ifdef __cplusplus
}
#endif

#endif
