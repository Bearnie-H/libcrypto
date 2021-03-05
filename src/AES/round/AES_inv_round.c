#include <stdint.h>

#include "include/AES_round.h"

void AES_InvRound(uint8_t *State, const uint32_t *RoundKey, AES_Block_Length_t BlockLength) {

    AES_InvShiftRows(State, BlockLength);
    AES_InvSubBytes(State, BlockLength);
    AES_AddRoundKey(State, RoundKey, BlockLength);
    AES_InvMixColumns(State, BlockLength);

    return;
}

void AES_InvSubBytes(uint8_t *State, AES_Block_Length_t BlockLength) {

    size_t ByteIndex;
    size_t WordIndex;
    uint8_t *Temp;

    for (WordIndex = 0; WordIndex < (size_t)BlockLength; WordIndex++) {
        for (ByteIndex = 0; ByteIndex < (int)sizeof(uint32_t); ByteIndex++) {
            Temp = &((uint8_t *)State)[ByteIndex + sizeof(uint32_t) * WordIndex];
            *Temp = Inv_S_Box[*Temp];
        }
    }

    return;
}

void AES_InvShiftRows(uint8_t *State, AES_Block_Length_t BlockLength) {

    int RowIndex;

    for (RowIndex = 1; RowIndex < (int)sizeof(uint32_t); RowIndex++) {

        /*
            Note:

            For the full Rijndael cipher, the ShiftSize and RowIndex are not necessarily
            equal for all Block Sizes. This is specifically designed for the AES
            implementation which restricts block size to 128-bits and enforces that
            RowIndex and ShiftSize will always be equal in magnitude.

            Should this library require extension to cover the full Rijndael cipher,
            this function call must be modified to pass the correct shift size.

            The actual function logic itself should work with block sizes
            other than 128-bits.
        */
        AES_ShiftRow(State, BlockLength, RowIndex, -RowIndex);
    }

    return;
}

void AES_InvMixColumns(uint8_t *State, AES_Block_Length_t BlockLength) {

    size_t ColumnIndex, RowIndex;
    uint8_t TempColumn[sizeof(uint32_t)] = {0};

    for (ColumnIndex = 0; ColumnIndex < (size_t)BlockLength; ColumnIndex++) {
        for (RowIndex = 0; RowIndex < (int)sizeof(uint32_t); RowIndex++) {
            TempColumn[RowIndex] = 0;
            TempColumn[RowIndex] ^= AES_GFMultiply(
                State[ColumnIndex * BlockLength + ((RowIndex + 0) % sizeof(uint32_t))], 0x0e);
            TempColumn[RowIndex] ^= AES_GFMultiply(
                State[ColumnIndex * BlockLength + ((RowIndex + 1) % sizeof(uint32_t))], 0x0b);
            TempColumn[RowIndex] ^= AES_GFMultiply(
                State[ColumnIndex * BlockLength + ((RowIndex + 2) % sizeof(uint32_t))], 0x0d);
            TempColumn[RowIndex] ^= AES_GFMultiply(
                State[ColumnIndex * BlockLength + ((RowIndex + 3) % sizeof(uint32_t))], 0x09);
        }
        for (RowIndex = 0; RowIndex < (int)sizeof(uint32_t); RowIndex++) {
            State[ColumnIndex * BlockLength + RowIndex] = TempColumn[RowIndex];
        }
    }

    return;
}
