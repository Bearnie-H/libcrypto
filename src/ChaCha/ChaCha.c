#include <stdio.h>
#include <string.h>

#include "context/include/ChaCha_context.h"
#include "include/ChaCha.h"
#include "round/include/ChaCha_round.h"

void ChaCha_Build_State(ChaCha_Context_t *Context, uint32_t *Counter, uint32_t *State) {

    memcpy(&(State[0]), ChaChaConstant, sizeof(ChaChaConstant) / sizeof(ChaChaConstant[0]));
    memcpy(&(State[4]), Context->Key, ChaCha_Key_256 * sizeof(uint32_t));
    memcpy(&(State[12]), Counter, CHACHA_COUNTER_LENGTH * sizeof(uint32_t));
    memcpy(&(State[13]), Context->Nonce, CHACHA_NONCE_LENGTH * sizeof(uint32_t));

    return;
}

void ChaCha_Next_Block(ChaCha_Context_t *Context, uint32_t *Counter) {

    int Index;

    ChaCha_Build_State(Context, Counter, Context->State);

    memcpy(Context->Keystream, Context->State, Context->BlockLength * sizeof(uint32_t));

    ChaCha_Rounds(Context->Keystream, Context->NumRounds);

    for (Index = 0; Index < (int)Context->BlockLength; Index++) {
        Context->Keystream[Index] += Context->State[Index];
    }

    (*Counter)++;

    return;
}
