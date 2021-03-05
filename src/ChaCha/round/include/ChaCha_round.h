#ifndef LIBCRYPTO_CHACHA_ROUND_H
#define LIBCRYPTO_CHACHA_ROUND_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#include "../../include/ChaCha.h"

void ChaCha_Rounds(uint32_t *State, ChaCha_Round_Count_t NumRounds);
void ChaCha_Round(uint32_t *State);
void ChaCha_EvenRound(uint32_t *State);
void ChaCha_OddRound(uint32_t *State);
void ChaCha_QuarterRound(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);
uint32_t ChaCha_Rotate_Left(uint32_t Word, size_t ShiftSize);

#if defined(TESTING) || defined(DEBUGGER)

#include "ChaCha_round_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
