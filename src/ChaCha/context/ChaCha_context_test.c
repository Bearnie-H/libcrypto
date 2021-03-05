#include <stdio.h>
#include <string.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "../include/ChaCha.h"
#include "include/ChaCha_context.h"

int Test_ChaCha_Context(void) {

    int FailedTests = 0;

    FailedTests += Test_ChaCha_Context_Prepare();

    return FailedTests;
}

int Test_ChaCha_Context_Prepare(void) {

    uint32_t Counter = 1;

    ChaCha_Context_t *Context =
        ChaCha_Context_Prepare(ChaCha_Test_Key_256, ChaCha_Test_Nonce, &(Counter));
    if (NULL == Context) {
        printf("Test_ChaCha_Context_Prepare() Failure: Failed to create ChaCha_Context_t!\n");
        return 1;
    }

    if ((NULL == Context->Key) || (NULL == Context->Nonce) || (NULL == Context->E_Counter) ||
        (NULL == Context->D_Counter) || (NULL == Context->State) || (NULL == Context->Keystream)) {
        printf("Test_ChaCha_Context_Prepare() Failure: NULL pointer within initialized context!\n");
        return 1;
    }

    ChaCha_Context_Release(Context);
    return 0;
}

#endif
