#include <stdlib.h>
#include <string.h>

#include "../include/AES.h"

AES_Context_t *
AES_Context_Prepare(AES_Block_Length_t BlockLength, AES_Key_Length_t KeyLength, const void *Key) {

    AES_Context_t *Context = NULL;

    if (NULL == Key) {
        return NULL;
    }

    Context = (AES_Context_t *)calloc(1, sizeof(AES_Context_t));
    if (NULL == Context) {
        return NULL;
    }

    Context->BlockLength = BlockLength;
    Context->KeyWords = KeyLength;

    switch (Context->KeyWords) {
    case AES_Key_128:
        Context->NumRounds = AES_Round_10;
        break;
    case AES_Key_192:
        Context->NumRounds = AES_Round_12;
        break;
    case AES_Key_256:
        Context->NumRounds = AES_Round_14;
        break;
    }

    Context->RoundKeyLength = (size_t)(Context->BlockLength * (Context->NumRounds + 1));
    Context->RoundKeys = (uint32_t *)calloc(Context->RoundKeyLength, sizeof(uint32_t));
    if (NULL == Context->RoundKeys) {
        AES_Context_Release(Context);
        return NULL;
    }

    if (0 !=
        AES_KeyExpansion(Key, Context->KeyWords, Context->RoundKeys, Context->RoundKeyLength)) {
        AES_Context_Release(Context);
        return NULL;
    }

    Context->State = (uint8_t *)calloc(Context->BlockLength, sizeof(uint32_t));
    if (NULL == Context->State) {
        AES_Context_Release(Context);
        return NULL;
    }

    return Context;
}

int AES_KeyExpansion(const void *Key,
                     size_t KeyWords,
                     uint32_t *KeySchedule,
                     size_t KeyScheduleLength) {

    size_t WordIndex = 0;
    uint32_t Temp = 0;

    for (WordIndex = 0; WordIndex < KeyWords; WordIndex++) {
        (KeySchedule)[WordIndex] = ((const uint32_t *)Key)[WordIndex];
    }

    for (WordIndex = KeyWords; WordIndex < KeyScheduleLength; WordIndex++) {
        Temp = (KeySchedule)[WordIndex - 1];

        if (0 == (WordIndex % KeyWords)) {
            Temp = SubWord(RotWord(Temp)) ^ RoundConstants[WordIndex / KeyWords];
        } else if ((KeyWords > AES_Key_192) && (AES_Key_128 == (WordIndex % KeyWords))) {
            Temp = SubWord(Temp);
        }

        Temp ^= (KeySchedule)[WordIndex - KeyWords];
        (KeySchedule)[WordIndex] = Temp;
    }

    return 0;
}

size_t AES_BlockLength(AES_Context_t *Ctx) {

    if (NULL == Ctx) {
        return 0;
    }

    return (size_t)Ctx->BlockLength * sizeof(uint32_t);
}

void AES_Context_Release(AES_Context_t *Ctx) {

    if (NULL == Ctx) {
        return;
    }

    if (NULL != Ctx->State) {
        memset(Ctx->State, 0x00, Ctx->BlockLength * sizeof(uint32_t));
        free(Ctx->State);
        Ctx->State = NULL;
    }

    if (NULL != Ctx->RoundKeys) {
        memset(Ctx->RoundKeys, 0x00, Ctx->RoundKeyLength * sizeof(uint32_t));
        free(Ctx->RoundKeys);
        Ctx->RoundKeys = NULL;
    }

    free(Ctx);

    return;
}

/*
    Private Function Definitions
*/
uint32_t SubWord(uint32_t Word) {

    uint8_t *Temp = (uint8_t *)(&(Word));
    Temp[0] = S_Box[Temp[0]];
    Temp[1] = S_Box[Temp[1]];
    Temp[2] = S_Box[Temp[2]];
    Temp[3] = S_Box[Temp[3]];

    return Word;
}

uint32_t RotWord(uint32_t Word) {

    uint8_t *Temp = (uint8_t *)(&(Word));
    uint8_t TempByte = Temp[0];

    Temp[0] = Temp[1];
    Temp[1] = Temp[2];
    Temp[2] = Temp[3];
    Temp[3] = TempByte;

    return Word;
}
