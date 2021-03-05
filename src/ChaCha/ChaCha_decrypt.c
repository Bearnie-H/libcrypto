#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "context/include/ChaCha_context.h"
#include "include/ChaCha.h"
#include "round/include/ChaCha_round.h"

int ChaCha_Decrypt_Block(ChaCha_Context_t *Context, const void *In, ssize_t Length, uint8_t *Out) {

    const uint8_t *InBytes = (const uint8_t *)In;
    uint8_t *OutBytes = (uint8_t *)Out;
    int Index;

    if (Length > (ssize_t)(Context->BlockLength * sizeof(uint32_t))) {
        Length = (ssize_t)Context->BlockLength;
    }

    ChaCha_Next_Block(Context, Context->D_Counter);
    (*Context->D_Counter)++;

    for (Index = 0; Index < (int)Length; Index++) {
        OutBytes[Index] = ((uint8_t *)Context->Keystream)[Index] ^ InBytes[Index];
    }

    return 0;
}
