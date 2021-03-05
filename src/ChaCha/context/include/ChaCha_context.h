#ifndef LIBCRYPTO_CHACHA_CONTEXT_H
#define LIBCRYPTO_CHACHA_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "../../include/ChaCha_constants.h"
typedef struct ChaCha_Context_t {

    uint32_t *Key;
    uint32_t *Nonce;
    uint32_t *E_Counter;
    uint32_t *D_Counter;

    uint32_t *State;
    uint32_t *Keystream;

    size_t BlockLength;
    ChaCha_Round_Count_t NumRounds;

} ChaCha_Context_t;

ChaCha_Context_t *ChaCha_Context_Prepare(const void *Key, const void *Nonce, const void *Counter);

size_t ChaCha_Block_Length(ChaCha_Context_t *Context);

void ChaCha_Context_Release(ChaCha_Context_t *Context);

#if defined(TESTING) || defined(DEBUGGER)

#include "ChaCha_context_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
