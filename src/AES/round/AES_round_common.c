#include <stdlib.h>

#include "include/AES_round.h"

void AES_AddRoundKey(uint8_t *State, const uint32_t *RoundKey, AES_Block_Length_t BlockLength) {

    size_t WordIndex;
    size_t ByteIndex;
    const uint8_t *RoundKeyBytes = (const uint8_t *)RoundKey;

    for (WordIndex = 0; WordIndex < (size_t)BlockLength; WordIndex++) {
        for (ByteIndex = 0; ByteIndex < sizeof(uint32_t); ByteIndex++) {
            uint8_t StateByte = State[WordIndex * BlockLength + ByteIndex];
            uint8_t RoundKeyByte = RoundKeyBytes[WordIndex * BlockLength + ByteIndex];
            State[WordIndex * BlockLength + ByteIndex] = StateByte ^ RoundKeyByte;
        }
    }

    return;
}

void AES_ShiftRow(uint8_t *State, AES_Block_Length_t BlockLength, int RowIndex, int ShiftSize) {

    int ByteIndex;
    int StartIndex, StepSize;
    int FinalSwapIndex;
    int SwapIndexA, SwapIndexB;

    if ((int)ABS(ShiftSize) > (int)(BlockLength / 2)) {
        ShiftSize = (ABS(ShiftSize) - (int)BlockLength) * (ShiftSize / ABS(ShiftSize));
    }

    if (ShiftSize < 0) {
        StartIndex = (int)BlockLength - 1;
        StepSize = -1;
        FinalSwapIndex = ABS(ShiftSize) - 1;
    } else {
        StartIndex = 0;
        StepSize = 1;
        FinalSwapIndex = (int)BlockLength - ABS(ShiftSize);
    }

    for (ByteIndex = StartIndex; ByteIndex != FinalSwapIndex; ByteIndex += StepSize) {

        SwapIndexA = ((int)sizeof(uint32_t) * ByteIndex) + RowIndex;
        SwapIndexB = (((ByteIndex - ShiftSize + (int)BlockLength) % (int)BlockLength) *
                      (int)sizeof(uint32_t)) +
                     RowIndex;
        AES_Swap_Bytes((uint8_t *)&(State[SwapIndexA]), (uint8_t *)&(State[SwapIndexB]));
    }

    return;
}

void AES_Swap_Bytes(uint8_t *A, uint8_t *B) {

    uint8_t Temp = *A;
    *A = *B;
    *B = Temp;

    return;
}

uint8_t AES_GFMultiply(uint8_t a, uint8_t b) {

    uint8_t Product = 0;
    while ((0 != a) && (0 != b)) {

        if (b & 1) {
            Product ^= a;
        }

        b >>= 1;

        if (a & 0x80) {
            a <<= 1;
            a ^= 0x1b;
        } else {
            a <<= 1;
        }
    }

    return Product;
}
