#ifndef LIBCRYPTO_AES_ROUND_H
#define LIBCRYPTO_AES_ROUND_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../include/AES.h"

/*
    Macro Definitions
*/
#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))
#define ABS(x) ((x) < 0 ? -(x) : (x))

void AES_Round(uint8_t *State, const uint32_t *RoundKey, AES_Block_Length_t BlockLength);
void AES_InvRound(uint8_t *State, const uint32_t *RoundKey, AES_Block_Length_t BlockLength);

void AES_AddRoundKey(uint8_t *State, const uint32_t *RoundKey, AES_Block_Length_t BlockLength);

void AES_SubBytes(uint8_t *State, AES_Block_Length_t BlockLength);
void AES_ShiftRows(uint8_t *State, AES_Block_Length_t BlockLength);
void AES_MixColumns(uint8_t *State, AES_Block_Length_t BlockLength);

void AES_InvSubBytes(uint8_t *State, AES_Block_Length_t BlockLength);
void AES_InvShiftRows(uint8_t *State, AES_Block_Length_t BlockLength);
void AES_InvMixColumns(uint8_t *State, AES_Block_Length_t BlockLength);

/*
    Internal helper functions
*/
uint8_t AES_GFMultiply(uint8_t a, uint8_t b);
void AES_ShiftRow(uint8_t *State, AES_Block_Length_t BlockLength, int RowIndex, int ShiftSize);
void AES_Swap_Bytes(uint8_t *A, uint8_t *B);

#if defined(TESTING) || defined(DEBUGGER)

#include "AES_round_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
