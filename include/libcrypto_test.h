#ifndef LIBCRYPTO_TEST_H
#define LIBCRYPTO_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../src/cipher/include/cipher.h"
#include "../src/AES/include/AES.h"
#include "../src/ChaCha/include/ChaCha.h"

int Test_Libcrypto(void);

#ifdef __cplusplus
}
#endif

#endif
