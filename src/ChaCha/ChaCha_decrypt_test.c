#include <stdio.h>
#include <string.h>

#include "context/include/ChaCha_context.h"
#include "include/ChaCha.h"

#if defined(TESTING) || defined(DEBUGGER)

int Test_ChaCha_Decrypt_Block(void) {

    const uint8_t Expected[] = "Ladies and Gentlemen of the class of '99: If I could offer you o";

    const uint8_t TestMessage[] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd,
        0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27,
        0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33,
        0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24,
        0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
    };

    uint8_t Temp[sizeof(TestMessage)] = {0x00};
    uint32_t Counter = 1;
    uint8_t Nonce[] = {
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x4a,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    ChaCha_Context_t *Context = ChaCha_Context_Prepare(ChaCha_Test_Key_256, Nonce, &Counter);
    if (NULL == Context) {
        printf("Test_ChaCha_Decrypt_Block() Failure: Failed to prepare testing Context!\n");
        return 1;
    }

    if (0 != ChaCha_Decrypt_Block(Context, (const void *)TestMessage, sizeof(TestMessage), Temp)) {
        printf("Test_ChaCha_Decrypt_Block() Failure: Error during ChaCha_Decrypt_Block()!\n");
        ChaCha_Context_Release(Context);
        return 1;
    }

    if (0 != memcmp(Temp, Expected, sizeof(TestMessage))) {
        printf("Test_ChaCha_Decrypt_Block() Failure: Plaintext does not match expected value!\n");
        ChaCha_Context_Release(Context);
        return 1;
    }

    ChaCha_Context_Release(Context);
    return 0;
}

#endif
