#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "../include/ChaCha.h"
#include "include/ChaCha_round.h"

int Test_ChaCha_RoundFuncs(void) {

    int FailedTests = 0;

    FailedTests += Test_ChaCha_Rotate_Left();
    FailedTests += Test_ChaCha_QuarterRound();
    FailedTests += Test_ChaCha_Rounds();

    return FailedTests;
}

int Test_ChaCha_Rounds(void) {

    const uint8_t *Key = (const uint8_t *)ChaCha_Test_Key_256;
    uint32_t Counter = 1;
    const uint8_t *Nonce = (const uint8_t *)ChaCha_Test_Nonce;

    uint32_t State[ChaCha_Block_512];

    uint32_t ExpectedState[ChaCha_Block_512] = {
        0x837778AB,
        0xE238D763,
        0xA67AE21E,
        0x5950BB2F,
        0xC4F2D0C7,
        0xFC62BB2F,
        0x8FA018FC,
        0x3F5EC7B7,
        0x335271C2,
        0xF29489F3,
        0xEABDA8FC,
        0x82E46EBD,
        0xD19C12B4,
        0xB04E16DE,
        0x9E83D0CB,
        0x4E3C50A2,
    };

    memcpy(&(State[0]), ChaChaConstant, 16);
    memcpy(&(State[4]), Key, 32);
    memcpy(&(State[12]), &Counter, 4);
    memcpy(&(State[13]), Nonce, 12);

    ChaCha_Rounds(State, ChaCha_Round_20);

    if (0 != memcmp(State, ExpectedState, sizeof(ExpectedState))) {
        printf("Test_ChaCha_Rounds() Failure: Output state does not match expectation!\n");
        return 1;
    }

    return 0;
}

int Test_ChaCha_QuarterRound(void) {

    uint32_t State[] = {
        0x879531E0,
        0xC5ECF37D,
        0x516461B1,
        0xC9A62F8A,
        0x44C20EF3,
        0x3390AF7F,
        0xD9FC690B,
        0x2A5F714C,
        0x53372767,
        0xB00A5631,
        0x974C541A,
        0x359E9963,
        0x5C971061,
        0x3D631689,
        0x2098D9D6,
        0x91DBD320,
    };

    uint32_t ExpectedFinalState[] = {
        0x879531E0,
        0xC5ECF37D,
        0xBDB886DC,
        0xC9A62F8A,
        0x44C20EF3,
        0x3390AF7F,
        0xD9FC690B,
        0xCFACAFD2,
        0xE46BEA80,
        0xB00A5631,
        0x974C541A,
        0x359E9963,
        0x5C971061,
        0xCCC07C79,
        0x2098D9D6,
        0x91DBD320,
    };

    ChaCha_QuarterRound(&(State[2]), &(State[7]), &(State[8]), &(State[13]));

    if (0 != memcmp(State, ExpectedFinalState, sizeof(ExpectedFinalState))) {
        printf("Test_ChaCha_QuarterRound() Failure: Output does not match expected value!\n");
        return 1;
    }

    return 0;
}

int Test_ChaCha_Rotate_Left(void) {

    uint32_t InputValue = 0xDEADBEEF;
    uint32_t OutputValue;
    size_t ShiftSize = 17;
    uint32_t ExpectedOutput = 0x7DDFBD5B;

    OutputValue = ChaCha_Rotate_Left(InputValue, ShiftSize);

    if (ExpectedOutput != OutputValue) {
        printf("Test_ChaCha_Rotate_Left() Failure: Output does not match expected value!\n");
        return 1;
    }

    return 0;
}

#endif
