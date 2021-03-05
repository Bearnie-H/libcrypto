#include <stdlib.h>
#include <string.h>

#include "../include/ChaCha.h"
#include "../include/ChaCha_constants.h"
#include "include/ChaCha_context.h"

ChaCha_Context_t *ChaCha_Context_Prepare(const void *Key, const void *Nonce, const void *Counter) {

    ChaCha_Context_t *Context = NULL;

    if (NULL == Key) {
        return NULL;
    }

    Context = (ChaCha_Context_t *)calloc(1, sizeof(ChaCha_Context_t));
    if (NULL == Context) {
        return NULL;
    }

    Context->BlockLength = ChaCha_Block_512;
    Context->NumRounds = ChaCha_Round_20;

    Context->D_Counter = (uint32_t *)calloc(CHACHA_COUNTER_LENGTH, sizeof(uint32_t));
    if (NULL == Context->D_Counter) {
        ChaCha_Context_Release(Context);
        return NULL;
    }
    memcpy(Context->D_Counter, Counter, (CHACHA_COUNTER_LENGTH * sizeof(uint32_t)));

    Context->E_Counter = (uint32_t *)calloc(CHACHA_COUNTER_LENGTH, sizeof(uint32_t));
    if (NULL == Context->E_Counter) {
        ChaCha_Context_Release(Context);
        return NULL;
    }
    memcpy(Context->E_Counter, Counter, (CHACHA_COUNTER_LENGTH * sizeof(uint32_t)));

    Context->Nonce = (uint32_t *)calloc(CHACHA_NONCE_LENGTH, sizeof(uint32_t));
    if (NULL == Context->Nonce) {
        ChaCha_Context_Release(Context);
        return NULL;
    }
    memcpy(Context->Nonce, Nonce, (CHACHA_NONCE_LENGTH * sizeof(uint32_t)));

    Context->Key = (uint32_t *)calloc(ChaCha_Key_256, sizeof(uint32_t));
    if (NULL == Context->Key) {
        ChaCha_Context_Release(Context);
        return NULL;
    }
    memcpy(Context->Key, Key, (ChaCha_Key_256 * sizeof(uint32_t)));

    Context->Keystream = (uint32_t *)calloc(Context->BlockLength, sizeof(uint32_t));
    if (NULL == Context->Keystream) {
        ChaCha_Context_Release(Context);
        return NULL;
    }

    Context->State = (uint32_t *)calloc(Context->BlockLength, sizeof(uint32_t));
    if (NULL == Context->State) {
        ChaCha_Context_Release(Context);
        return NULL;
    }

    return Context;
}

size_t ChaCha_Block_Length(ChaCha_Context_t *Context) {
    return Context->BlockLength * sizeof(uint32_t);
}

void ChaCha_Context_Release(ChaCha_Context_t *Context) {

    if (NULL == Context) {
        return;
    }

    if (NULL != Context->Key) {
        memset(Context->Key, 0x00, ChaCha_Key_256);
        free(Context->Key);
        Context->Key = NULL;
    }

    if (NULL != Context->Nonce) {
        memset(Context->Nonce, 0x00, CHACHA_NONCE_LENGTH);
        free(Context->Nonce);
        Context->Nonce = NULL;
    }

    if (NULL != Context->E_Counter) {
        memset(Context->E_Counter, 0x00, CHACHA_COUNTER_LENGTH);
        free(Context->E_Counter);
        Context->E_Counter = NULL;
    }

    if (NULL != Context->D_Counter) {
        memset(Context->D_Counter, 0x00, CHACHA_COUNTER_LENGTH);
        free(Context->D_Counter);
        Context->D_Counter = NULL;
    }

    if (NULL != Context->Keystream) {
        memset(Context->Keystream, 0x00, Context->BlockLength);
        free(Context->Keystream);
        Context->Keystream = NULL;
    }

    if (NULL != Context->State) {
        memset(Context->State, 0x00, Context->BlockLength);
        free(Context->State);
        Context->State = NULL;
    }

    free(Context);

    return;
}
