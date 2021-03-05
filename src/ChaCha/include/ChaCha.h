#ifndef LIBCRYPTO_CHACHA_H
#define LIBCRYPTO_CHACHA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

#include "../context/include/ChaCha_context.h"
#include "ChaCha_constants.h"

int ChaCha_Encrypt_Block(ChaCha_Context_t *Context, const void *In, ssize_t Length, uint8_t *Out);
int ChaCha_Decrypt_Block(ChaCha_Context_t *Context, const void *In, ssize_t Length, uint8_t *Out);

void ChaCha_Build_State(ChaCha_Context_t *Context, uint32_t *Counter, uint32_t *State);
void ChaCha_Next_Block(ChaCha_Context_t *Context, uint32_t *Counter);

#if defined(TESTING) || defined(DEBUGGER)

#include "ChaCha_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
