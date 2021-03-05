#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "include/AES.h"

int Test_AES_Decrypt_Block(void) {

    int FailedTests = 0;

    FailedTests += Test_AES_Decrypt_Block_128();
    FailedTests += Test_AES_Decrypt_Block_192();
    FailedTests += Test_AES_Decrypt_Block_256();

    return FailedTests;
}

int Test_AES_Decrypt_Block_128(void) {

    uint8_t DecryptedVector[sizeof(uint32_t) * AES_Block_128] = {0};

    AES_Context_t *Context = AES_Context_Prepare(AES_Block_128, AES_Key_128, AES_Test_Key_128);
    if (NULL == Context) {
        printf("Test_AES_Decrypt_Block_128() Failure: Failed to create testing AES_Context_t!\n");
        return 1;
    }

    if (0 != AES_Decrypt_Block(Context,
                               AES_Test_Dec_InputVector_128,
                               sizeof(AES_Test_Dec_InputVector_128),
                               DecryptedVector)) {
        printf("Test_AES_Decrypt_Block_128() Failure: Error during AES_Decrypt_Block()!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (0 != memcmp(DecryptedVector, AES_Test_Enc_InputVector, sizeof(DecryptedVector))) {
        printf("Test_AES_Decrypt_Block_128() Failure: Decrypted vector does not match expected "
               "value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_AES_Decrypt_Block_192(void) {

    uint8_t DecryptedVector[sizeof(uint32_t) * AES_Block_128] = {0};

    AES_Context_t *Context = AES_Context_Prepare(AES_Block_128, AES_Key_192, AES_Test_Key_192);
    if (NULL == Context) {
        printf("Test_AES_Decrypt_Block_192() Failure: Failed to create testing AES_Context_t!\n");
        return 1;
    }

    if (0 != AES_Decrypt_Block(Context,
                               AES_Test_Dec_InputVector_192,
                               sizeof(AES_Test_Dec_InputVector_192),
                               DecryptedVector)) {
        printf("Test_AES_Decrypt_Block_192() Failure: Error during AES_Decrypt_Block()!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (0 != memcmp(DecryptedVector, AES_Test_Enc_InputVector, sizeof(DecryptedVector))) {
        printf("Test_AES_Decrypt_Block_192() Failure: Decrypted vector does not match expected "
               "value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

int Test_AES_Decrypt_Block_256(void) {

    uint8_t DecryptedVector[sizeof(uint32_t) * AES_Block_128] = {0};

    AES_Context_t *Context = AES_Context_Prepare(AES_Block_128, AES_Key_256, AES_Test_Key_256);
    if (NULL == Context) {
        printf("Test_AES_Decrypt_Block_256() Failure: Failed to create testing AES_Context_t!\n");
        return 1;
    }

    if (0 != AES_Decrypt_Block(Context,
                               AES_Test_Dec_InputVector_256,
                               sizeof(AES_Test_Dec_InputVector_256),
                               DecryptedVector)) {
        printf("Test_AES_Decrypt_Block_256() Failure: Error during AES_Decrypt_Block()!\n");
        AES_Context_Release(Context);
        return 1;
    }

    if (0 != memcmp(DecryptedVector, AES_Test_Enc_InputVector, sizeof(DecryptedVector))) {
        printf("Test_AES_Decrypt_Block_256() Failure: Decrypted vector does not match expected "
               "value!\n");
        AES_Context_Release(Context);
        return 1;
    }

    AES_Context_Release(Context);
    return 0;
}

#endif
