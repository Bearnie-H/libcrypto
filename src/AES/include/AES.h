#ifndef LIBCRYPTO_AES_H
#define LIBCRYPTO_AES_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../context/include/AES_context.h"
#include "AES_constants.h"

int AES_Encrypt_Block(AES_Context_t *Context, const void *In, size_t Length, uint8_t *Out);
int AES_Decrypt_Block(AES_Context_t *Context, const void *In, size_t Length, uint8_t *Out);

/*
    Apply an increment to the given Cipher IV value.

    This allows a simple implementation of the CTR mode of operation
    for the AES block cipher.
*/
void AES_Counter_Increment(void *Counter);

#if defined(TESTING) || defined(DEBUGGER)

#include "AES_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
