#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "../include/AES.h"
#include "include/AES_context.h"

int Test_AES_Context(void) {

    int FailedTests = 0;

    FailedTests += Test_SubWord();
    FailedTests += Test_RotWord();
    FailedTests += Test_AES_KeyExpansion();
    FailedTests += Test_AES_Context_Prepare();
    FailedTests += Test_AES_BlockLength();

    return FailedTests;
}

int Test_AES_Context_Prepare(void) {

    int FailedTests = 0;

    FailedTests += Test_AES_Context_Prepare_128();
    FailedTests += Test_AES_Context_Prepare_192();
    FailedTests += Test_AES_Context_Prepare_256();

    return FailedTests;
}

int Test_AES_Context_Prepare_128(void) {

    AES_Context_t *Context =
        AES_Context_Prepare(AES_Block_128, AES_Key_128, AES_Test_Expansion_Key_128);
    if (NULL == Context) {
        printf("Test_AES_Context_Prepare_128() Failure: Failed to allocate Context!\n");
        return 1;
    }

    if (Context->BlockLength != AES_Block_128) {
        printf(
            "Test_AES_Context_Prepare_128() Failure: Context block length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->KeyWords != AES_Key_128) {
        printf("Test_AES_Context_Prepare_128() Failure: Context key length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->NumRounds != AES_Round_10) {
        printf("Test_AES_Context_Prepare_128() Failure: Number of rounds not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->RoundKeyLength != (Context->BlockLength * (Context->NumRounds + 1))) {
        printf("Test_AES_Context_Prepare_128() Failure: Key Schedule length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->RoundKeys) {
        printf("Test_AES_Context_Prepare_128() Failure: NULL Key Schedule!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->State) {
        printf("Test_AES_Context_Prepare_128() Failure: NULL internal state!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_AES_Context_Prepare_192(void) {

    AES_Context_t *Context =
        AES_Context_Prepare(AES_Block_128, AES_Key_192, AES_Test_Expansion_Key_192);
    if (NULL == Context) {
        printf("Test_AES_Context_Prepare_192() Failure: Failed to allocate Context!\n");
        return 1;
    }

    if (Context->BlockLength != AES_Block_128) {
        printf(
            "Test_AES_Context_Prepare_192() Failure: Context block length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->KeyWords != AES_Key_192) {
        printf("Test_AES_Context_Prepare_192() Failure: Context key length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->NumRounds != AES_Round_12) {
        printf("Test_AES_Context_Prepare_192() Failure: Number of rounds not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->RoundKeyLength != (Context->BlockLength * (Context->NumRounds + 1))) {
        printf("Test_AES_Context_Prepare_192() Failure: Key Schedule length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->RoundKeys) {
        printf("Test_AES_Context_Prepare_192() Failure: NULL Key Schedule!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->State) {
        printf("Test_AES_Context_Prepare_192() Failure: NULL internal state!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_AES_Context_Prepare_256(void) {

    AES_Context_t *Context =
        AES_Context_Prepare(AES_Block_128, AES_Key_256, AES_Test_Expansion_Key_256);
    if (NULL == Context) {
        printf("Test_AES_Context_Prepare_256() Failure: Failed to allocate Context!\n");
        return 1;
    }

    if (Context->BlockLength != AES_Block_128) {
        printf(
            "Test_AES_Context_Prepare_256() Failure: Context block length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->KeyWords != AES_Key_256) {
        printf("Test_AES_Context_Prepare_256() Failure: Context key length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->NumRounds != AES_Round_14) {
        printf("Test_AES_Context_Prepare_256() Failure: Number of rounds not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (Context->RoundKeyLength != (Context->BlockLength * (Context->NumRounds + 1))) {
        printf("Test_AES_Context_Prepare_256() Failure: Key Schedule length not expected value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->RoundKeys) {
        printf("Test_AES_Context_Prepare_256() Failure: NULL Key Schedule!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (NULL == Context->State) {
        printf("Test_AES_Context_Prepare_256() Failure: NULL internal state!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_AES_KeyExpansion(void) {

    int FailedTests = 0;

    FailedTests += Test_AES_KeyExpansion_128();
    FailedTests += Test_AES_KeyExpansion_192();
    FailedTests += Test_AES_KeyExpansion_256();

    return FailedTests;
}

int Test_AES_KeyExpansion_128(void) {

    uint32_t ExpandedKey[sizeof(AES_Test_Key_128_Expanded) / sizeof(uint32_t)] = {0};
    if (0 != AES_KeyExpansion(AES_Test_Expansion_Key_128,
                              AES_Key_128,
                              ExpandedKey,
                              sizeof(ExpandedKey) / sizeof(uint32_t))) {
        printf("Test_AES_KeyExpansion_128() Failure: Error in KeyExpansion()!\n");
        return 1;
    }

    if (0 != memcmp(ExpandedKey, AES_Test_Key_128_Expanded, sizeof(AES_Test_Key_128_Expanded))) {
        printf(
            "Test_AES_KeyExpansion_128() Failure: Expanded Key does not match expected value!\n");
        return 1;
    }

    return 0;
}

int Test_AES_KeyExpansion_192(void) {

    uint32_t ExpandedKey[sizeof(AES_Test_Key_192_Expanded) / sizeof(uint32_t)] = {0};
    if (0 != AES_KeyExpansion(AES_Test_Expansion_Key_192,
                              AES_Key_192,
                              ExpandedKey,
                              sizeof(ExpandedKey) / sizeof(uint32_t))) {
        printf("Test_AES_KeyExpansion_192() Failure: Error in KeyExpansion()!\n");
        return 1;
    }

    if (0 != memcmp(ExpandedKey, AES_Test_Key_192_Expanded, sizeof(AES_Test_Key_192_Expanded))) {
        printf(
            "Test_AES_KeyExpansion_192() Failure: Expanded Key does not match expected value!\n");
        return 1;
    }

    return 0;
}

int Test_AES_KeyExpansion_256(void) {

    uint32_t ExpandedKey[sizeof(AES_Test_Key_256_Expanded) / sizeof(uint32_t)] = {0};
    if (0 != AES_KeyExpansion(AES_Test_Expansion_Key_256,
                              AES_Key_256,
                              ExpandedKey,
                              sizeof(ExpandedKey) / sizeof(uint32_t))) {
        printf("Test_AES_KeyExpansion_256() Failure: Error in KeyExpansion()!\n");
        return 1;
    }

    if (0 != memcmp(ExpandedKey, AES_Test_Key_256_Expanded, sizeof(AES_Test_Key_256_Expanded))) {
        printf(
            "Test_AES_KeyExpansion_256() Failure: Expanded Key does not match expected value!\n");
        return 1;
    }

    return 0;
}

int Test_AES_BlockLength(void) {

    AES_Context_t *Context =
        AES_Context_Prepare(AES_Block_128, AES_Key_128, AES_Test_Expansion_Key_128);
    if (NULL == Context) {
        printf("Test_AES_BlockLength() Failure: Failed to create Context for testing.\n");
        return 1;
    }

    if (AES_BlockLength(Context) != (AES_Block_128 * sizeof(uint32_t))) {
        printf("Test_AES_BlockLength() Failure: Block length not equal to expected value.\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_SubWord(void) {

    uint32_t InputWord = 0x2A05766C;
    uint32_t OutputWord;
    uint32_t ExpectedWord = 0xE56B3850;

    OutputWord = SubWord(InputWord);

    if (OutputWord != ExpectedWord) {
        printf("Test_SubWord() Failure: Output does not match expectation.\n");
        return 1;
    }

    return 0;
}

int Test_RotWord(void) {

    uint32_t InputWord = 0xAABBCCDD;
    uint32_t OutputWord;
    uint32_t ExpectedWord = 0xDDAABBCC;

    OutputWord = RotWord(InputWord);

    if (OutputWord != ExpectedWord) {
        printf("Test_RotWord() Failure: Output does not match expectation.\n");
        return 1;
    }

    return 0;
}

#endif
