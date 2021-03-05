#ifndef LIBCRYPTO_TEST_H
#define LIBCRYPTO_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../src/AES/include/AES.h"
#include "../src/ChaCha/include/ChaCha.h"
#include "../src/cipher/include/cipher.h"

int Test_Libcrypto(void);

#ifdef __cplusplus
}
#endif

#endif
