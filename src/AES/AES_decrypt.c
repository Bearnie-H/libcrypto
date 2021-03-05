#include <stdlib.h>
#include <string.h>

#include "include/AES.h"
#include "round/include/AES_round.h"

int AES_Decrypt_Block(AES_Context_t *Context, const void *In, size_t Length, uint8_t *Out) {

    int Round;
    uint32_t *RoundKey = &(Context->RoundKeys[Context->NumRounds * Context->BlockLength]);

    if ((NULL == In) || (NULL == Out)) {
        return -1;
    }

    if (0 == Length) {
        return 0;
    }

    memcpy(Context->State, In, Context->BlockLength * sizeof(uint32_t));

    AES_AddRoundKey(Context->State, RoundKey, Context->BlockLength);

    for (Round = (int)Context->NumRounds - 1; Round > 0; Round--) {
        RoundKey = &(Context->RoundKeys[(size_t)Round * Context->BlockLength]);
        AES_InvRound(Context->State, RoundKey, Context->BlockLength);
    }

    RoundKey = Context->RoundKeys;
    AES_InvShiftRows(Context->State, Context->BlockLength);
    AES_InvSubBytes(Context->State, Context->BlockLength);
    AES_AddRoundKey(Context->State, Context->RoundKeys, Context->BlockLength);

    memcpy(Out, Context->State, Context->BlockLength * sizeof(uint32_t));

    memset(Context->State, 0, Context->BlockLength * sizeof(uint32_t));

    return 0;
}
