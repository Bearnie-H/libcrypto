#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "include/AES_round.h"

int Test_AES_RoundFuncs(void) {

    int FailedTests = 0;

    FailedTests += Test_AES_AddRoundKey();

    FailedTests += Test_AES_SubBytes();
    FailedTests += Test_AES_ShiftRows();
    FailedTests += Test_AES_MixColumns();

    FailedTests += Test_AES_InvSubBytes();
    FailedTests += Test_AES_InvShiftRows();
    FailedTests += Test_AES_InvMixColumns();

    return FailedTests;
}

int Test_AES_SubBytes(void) {

    const uint8_t StartingVector[sizeof(uint32_t) * AES_Block_128] = {0x00,
                                                                      0x10,
                                                                      0x20,
                                                                      0x30,
                                                                      0x40,
                                                                      0x50,
                                                                      0x60,
                                                                      0x70,
                                                                      0x80,
                                                                      0x90,
                                                                      0xa0,
                                                                      0xb0,
                                                                      0xc0,
                                                                      0xd0,
                                                                      0xe0,
                                                                      0xf0};

    const uint8_t EndingVector[sizeof(uint32_t) * AES_Block_128] = {0x63,
                                                                    0xca,
                                                                    0xb7,
                                                                    0x04,
                                                                    0x09,
                                                                    0x53,
                                                                    0xd0,
                                                                    0x51,
                                                                    0xcd,
                                                                    0x60,
                                                                    0xe0,
                                                                    0xe7,
                                                                    0xba,
                                                                    0x70,
                                                                    0xe1,
                                                                    0x8c};

    uint8_t State[sizeof(uint32_t) * AES_Block_128];

    memcpy(State, StartingVector, sizeof(StartingVector));

    AES_SubBytes(State, AES_Block_128);

    if (0 != memcmp(State, EndingVector, sizeof(EndingVector))) {
        printf("Test_AES_SubBytes() Failure: Resultant vector does not match expected value.\n");
        return 1;
    }

    return 0;
}

int Test_AES_ShiftRows(void) {

    const uint8_t StartingRows[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                    0x27,
                                                                    0x11,
                                                                    0xae,
                                                                    0xe0,
                                                                    0xbf,
                                                                    0x98,
                                                                    0xf1,
                                                                    0xb8,
                                                                    0xb4,
                                                                    0x5d,
                                                                    0xe5,
                                                                    0x1e,
                                                                    0x41,
                                                                    0x52,
                                                                    0x30};

    const uint8_t EndingRows[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                  0xbf,
                                                                  0x5d,
                                                                  0x30,
                                                                  0xe0,
                                                                  0xb4,
                                                                  0x52,
                                                                  0xae,
                                                                  0xb8,
                                                                  0x41,
                                                                  0x11,
                                                                  0xf1,
                                                                  0x1e,
                                                                  0x27,
                                                                  0x98,
                                                                  0xe5};

    uint8_t State[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                       0x27,
                                                       0x11,
                                                       0xae,
                                                       0xe0,
                                                       0xbf,
                                                       0x98,
                                                       0xf1,
                                                       0xb8,
                                                       0xb4,
                                                       0x5d,
                                                       0xe5,
                                                       0x1e,
                                                       0x41,
                                                       0x52,
                                                       0x30};

    if (0 != memcmp(State, StartingRows, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_ShiftRows() Failure: State and StartingRows do not match.\n");
        return 1;
    }

    AES_ShiftRows(State, AES_Block_128);

    if (0 != memcmp(State, EndingRows, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_ShiftRows() Failure: State and EndingRows do not match.\n");
        return 1;
    }

    return 0;
}

int Test_AES_MixColumns(void) {

    const uint8_t StartingColumns[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                       0xbf,
                                                                       0x5d,
                                                                       0x30,
                                                                       0xe0,
                                                                       0xb4,
                                                                       0x52,
                                                                       0xae,
                                                                       0xb8,
                                                                       0x41,
                                                                       0x11,
                                                                       0xf1,
                                                                       0x1e,
                                                                       0x27,
                                                                       0x98,
                                                                       0xe5};

    const uint8_t EndingColumns[sizeof(uint32_t) * AES_Block_128] = {0x04,
                                                                     0x66,
                                                                     0x81,
                                                                     0xe5,
                                                                     0xe0,
                                                                     0xcb,
                                                                     0x19,
                                                                     0x9a,
                                                                     0x48,
                                                                     0xf8,
                                                                     0xd3,
                                                                     0x7a,
                                                                     0x28,
                                                                     0x06,
                                                                     0x26,
                                                                     0x4c};

    uint8_t State[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                       0xbf,
                                                       0x5d,
                                                       0x30,
                                                       0xe0,
                                                       0xb4,
                                                       0x52,
                                                       0xae,
                                                       0xb8,
                                                       0x41,
                                                       0x11,
                                                       0xf1,
                                                       0x1e,
                                                       0x27,
                                                       0x98,
                                                       0xe5};

    if (0 != memcmp(State, StartingColumns, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_MixColumns() Failure: State and StartingColumns do not match.\n");
        return 1;
    }

    AES_MixColumns(State, AES_Block_128);

    if (0 != memcmp(State, EndingColumns, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_MixColumns() Failure: State and EndingColumns do not match.\n");
        return 1;
    }

    return 0;
}

int Test_AES_AddRoundKey(void) {

    const uint8_t KeySchedule[sizeof(uint32_t) * AES_Block_128] = {0x00,
                                                                   0x01,
                                                                   0x02,
                                                                   0x03,
                                                                   0x04,
                                                                   0x05,
                                                                   0x06,
                                                                   0x07,
                                                                   0x08,
                                                                   0x09,
                                                                   0x0a,
                                                                   0x0b,
                                                                   0x0c,
                                                                   0x0d,
                                                                   0x0e,
                                                                   0x0f};

    const uint8_t StartingVector[sizeof(uint32_t) * AES_Block_128] = {0x00,
                                                                      0x11,
                                                                      0x22,
                                                                      0x33,
                                                                      0x44,
                                                                      0x55,
                                                                      0x66,
                                                                      0x77,
                                                                      0x88,
                                                                      0x99,
                                                                      0xaa,
                                                                      0xbb,
                                                                      0xcc,
                                                                      0xdd,
                                                                      0xee,
                                                                      0xff};

    const uint8_t EndingVector[sizeof(uint32_t) * AES_Block_128] = {0x00,
                                                                    0x10,
                                                                    0x20,
                                                                    0x30,
                                                                    0x40,
                                                                    0x50,
                                                                    0x60,
                                                                    0x70,
                                                                    0x80,
                                                                    0x90,
                                                                    0xa0,
                                                                    0xb0,
                                                                    0xc0,
                                                                    0xd0,
                                                                    0xe0,
                                                                    0xf0};

    uint8_t State[sizeof(uint32_t) * AES_Block_128];

    memcpy(State, StartingVector, sizeof(StartingVector));

    AES_AddRoundKey((uint8_t *)State, (const uint32_t *)KeySchedule, AES_Block_128);

    if (0 != memcmp(State, EndingVector, sizeof(EndingVector))) {
        printf("Test_AES_AddRoundKey() Failure: Resultant vector does not match expected value.\n");
        return 1;
    }

    return 0;
}

int Test_AES_InvSubBytes(void) {

    const uint8_t StartingVector[sizeof(uint32_t) * AES_Block_128] = {0x63,
                                                                      0xca,
                                                                      0xb7,
                                                                      0x04,
                                                                      0x09,
                                                                      0x53,
                                                                      0xd0,
                                                                      0x51,
                                                                      0xcd,
                                                                      0x60,
                                                                      0xe0,
                                                                      0xe7,
                                                                      0xba,
                                                                      0x70,
                                                                      0xe1,
                                                                      0x8c};

    const uint8_t EndingVector[sizeof(uint32_t) * AES_Block_128] = {0x00,
                                                                    0x10,
                                                                    0x20,
                                                                    0x30,
                                                                    0x40,
                                                                    0x50,
                                                                    0x60,
                                                                    0x70,
                                                                    0x80,
                                                                    0x90,
                                                                    0xa0,
                                                                    0xb0,
                                                                    0xc0,
                                                                    0xd0,
                                                                    0xe0,
                                                                    0xf0};

    uint8_t State[sizeof(uint32_t) * AES_Block_128] = {0x00};

    memcpy(State, StartingVector, sizeof(StartingVector));

    AES_InvSubBytes(State, AES_Block_128);

    if (0 != memcmp(State, EndingVector, sizeof(EndingVector))) {
        printf("Test_AES_InvSubBytes() Failure: Resultant vector does not match expected value.\n");
        return 1;
    }

    return 0;
}

int Test_AES_InvShiftRows(void) {

    const uint8_t StartingRows[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                    0xbf,
                                                                    0x5d,
                                                                    0x30,
                                                                    0xe0,
                                                                    0xb4,
                                                                    0x52,
                                                                    0xae,
                                                                    0xb8,
                                                                    0x41,
                                                                    0x11,
                                                                    0xf1,
                                                                    0x1e,
                                                                    0x27,
                                                                    0x98,
                                                                    0xe5};

    const uint8_t EndingRows[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                  0x27,
                                                                  0x11,
                                                                  0xae,
                                                                  0xe0,
                                                                  0xbf,
                                                                  0x98,
                                                                  0xf1,
                                                                  0xb8,
                                                                  0xb4,
                                                                  0x5d,
                                                                  0xe5,
                                                                  0x1e,
                                                                  0x41,
                                                                  0x52,
                                                                  0x30};

    uint8_t State[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                       0xbf,
                                                       0x5d,
                                                       0x30,
                                                       0xe0,
                                                       0xb4,
                                                       0x52,
                                                       0xae,
                                                       0xb8,
                                                       0x41,
                                                       0x11,
                                                       0xf1,
                                                       0x1e,
                                                       0x27,
                                                       0x98,
                                                       0xe5};

    if (0 != memcmp(State, StartingRows, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_InvShiftRows() Failure: State and StartingRows do not match.\n");
        return 1;
    }

    AES_InvShiftRows(State, AES_Block_128);

    if (0 != memcmp(State, EndingRows, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_InvShiftRows() Failure: State and EndingRows do not match.\n");
        return 1;
    }

    return 0;
}

int Test_AES_InvMixColumns(void) {

    const uint8_t StartingColumns[sizeof(uint32_t) * AES_Block_128] = {0x04,
                                                                       0x66,
                                                                       0x81,
                                                                       0xe5,
                                                                       0xe0,
                                                                       0xcb,
                                                                       0x19,
                                                                       0x9a,
                                                                       0x48,
                                                                       0xf8,
                                                                       0xd3,
                                                                       0x7a,
                                                                       0x28,
                                                                       0x06,
                                                                       0x26,
                                                                       0x4c};

    const uint8_t EndingColumns[sizeof(uint32_t) * AES_Block_128] = {0xd4,
                                                                     0xbf,
                                                                     0x5d,
                                                                     0x30,
                                                                     0xe0,
                                                                     0xb4,
                                                                     0x52,
                                                                     0xae,
                                                                     0xb8,
                                                                     0x41,
                                                                     0x11,
                                                                     0xf1,
                                                                     0x1e,
                                                                     0x27,
                                                                     0x98,
                                                                     0xe5};

    uint8_t State[sizeof(uint32_t) * AES_Block_128] = {0x04,
                                                       0x66,
                                                       0x81,
                                                       0xe5,
                                                       0xe0,
                                                       0xcb,
                                                       0x19,
                                                       0x9a,
                                                       0x48,
                                                       0xf8,
                                                       0xd3,
                                                       0x7a,
                                                       0x28,
                                                       0x06,
                                                       0x26,
                                                       0x4c};

    if (0 != memcmp(State, StartingColumns, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_InvMixColumns() Failure: State and StartingColumns do not match.\n");
        return 1;
    }

    AES_InvMixColumns(State, AES_Block_128);

    if (0 != memcmp(State, EndingColumns, sizeof(uint32_t) * AES_Block_128)) {
        printf("Test_AES_InvMixColumns() Failure: State and EndingColumns do not match.\n");
        return 1;
    }

    return 0;
}

#endif
