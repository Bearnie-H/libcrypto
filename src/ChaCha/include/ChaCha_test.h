#ifndef LIBCRYPTO_CHACHA_TEST_H
#define LIBCRYPTO_CHACHA_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int Test_ChaCha(void);

int Test_ChaCha_Encrypt_Block(void);
int Test_ChaCha_Decrypt_Block(void);

extern const uint8_t ChaCha_Test_Key_256[32];
extern const uint8_t ChaCha_Test_Nonce[12];

#ifdef __cplusplus
}
#endif

#endif
