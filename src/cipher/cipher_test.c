#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "../../include/libcrypto.h"
#include "../AES/include/AES.h"
#include "../ChaCha/include/ChaCha.h"
#include "include/cipher.h"

int Test_Cipher(void) {

    int FailedTests = 0;

    FailedTests += Test_Cipher_Prepare();
    FailedTests += Test_Cipher_Modes();

    return FailedTests;
}

int Test_Cipher_Prepare(void) {

    int FailedTests = 0;

    FailedTests += Test_Cipher_Prepare_AES();
    FailedTests += Test_Cipher_Prepare_ChaCha();

    return FailedTests;
}

int Test_Cipher_Prepare_AES(void) {

    Cipher_t *Cipher = Cipher_Prepare(AES_128, Cipher_Mode_CTR, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_Prepare_AES() Failure: Failed to create Cipher!\n");
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_Prepare_ChaCha(void) {

    Cipher_t *Cipher = Cipher_Prepare(ChaCha20, 0, ChaCha_Test_Key_256, ChaCha_Test_Nonce);
    if (NULL == Cipher) {
        printf("Test_Cipher_Prepare_ChaCha() Failure: Failed to create Cipher!\n");
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_Modes(void) {

    int FailedTests = 0;

    FailedTests += Test_Cipher_AES_ECB();
    FailedTests += Test_Cipher_AES_CBC();
    FailedTests += Test_Cipher_AES_CFB();
    FailedTests += Test_Cipher_AES_OFB();
    FailedTests += Test_Cipher_AES_CTR();
    FailedTests += Test_Cipher_ChaCha();

    return FailedTests;
}

int Test_Cipher_AES_ECB(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "Hello world! This is a test message to encrypt!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(AES_128, Cipher_Mode_ECB, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_AES_ECB() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_ECB() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_ECB() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_AES_ECB() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_AES_CBC(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "Hello world! This is a test message to encrypt!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(AES_128, Cipher_Mode_CBC, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_AES_CBC() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CBC() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CBC() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_AES_CBC() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_AES_CFB(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "Hello world! This is a test message to encrypt!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(AES_128, Cipher_Mode_CFB, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_AES_CFB() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CFB() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CFB() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_AES_CFB() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_AES_OFB(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "Hello world! This is a test message to encrypt!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(AES_128, Cipher_Mode_OFB, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_AES_OFB() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_OFB() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_OFB() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_AES_OFB() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_AES_CTR(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "Hello world! This is a test message to encrypt!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(AES_128, Cipher_Mode_CTR, AES_Test_Key_128, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_AES_CTR() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CTR() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage[0]))) {
        printf("Test_Cipher_AES_CTR() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_AES_CTR() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

int Test_Cipher_ChaCha(void) {

    Cipher_t *Cipher;
    const char TestMessage[] = "This is a testing message for the ChaCha20 encryption algorithm. "
                               "This is longer than one block!";
    char RoundTripMessage[sizeof(TestMessage)] = {0x00};
    memcpy(RoundTripMessage, TestMessage, sizeof(TestMessage));

    Cipher = Cipher_Prepare(ChaCha20, Cipher_Mode_ECB, ChaCha_Test_Key_256, NULL);
    if (NULL == Cipher) {
        printf("Test_Cipher_ChaCha() Failure: Failed to create testing Cipher!\n");
        return 1;
    }

    if (-1 == Cipher_Encrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage))) {
        printf("Test_Cipher_ChaCha() Failure: Error occured during Cipher_Encrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (-1 == Cipher_Decrypt(Cipher,
                             (const void *)&(RoundTripMessage[0]),
                             sizeof(RoundTripMessage),
                             (uint8_t *)&(RoundTripMessage))) {
        printf("Test_Cipher_ChaCha() Failure: Error occured during Cipher_Decrypt()!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    if (0 != memcmp(TestMessage, RoundTripMessage, sizeof(RoundTripMessage))) {
        printf("Test_Cipher_ChaCha() Failure: Message is not the same after encrypting and "
               "decrypting!\n");
        Cipher_Release(Cipher);
        return 1;
    }

    Cipher_Release(Cipher);
    return 0;
}

#endif
