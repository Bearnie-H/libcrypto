#ifndef LIBCRYPTO_AES_CONTEXT_TEST_H
#define LIBCRYPTO_AES_CONTEXT_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

/*
    Test_AES_Context

    This function will run all of the unit tests related to the AES_Context_t struct.

    Inputs:
    None

    Outputs:
    int -   The number of tests failed in this module.
*/
int Test_AES_Context(void);

int Test_AES_Context_Prepare(void);
int Test_AES_Context_Prepare_128(void);
int Test_AES_Context_Prepare_192(void);
int Test_AES_Context_Prepare_256(void);

int Test_AES_KeyExpansion(void);
int Test_AES_KeyExpansion_128(void);
int Test_AES_KeyExpansion_192(void);
int Test_AES_KeyExpansion_256(void);

int Test_AES_BlockLength(void);
int Test_SubWord(void);
int Test_RotWord(void);

#ifdef __cplusplus
}
#endif

#endif
