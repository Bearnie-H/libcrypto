#include <stdio.h>
#include <stdlib.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "context/include/ChaCha_context.h"
#include "include/ChaCha.h"
#include "round/include/ChaCha_round.h"

int Test_ChaCha(void) {

    int FailedTests = 0;

    FailedTests += Test_ChaCha_Context();
    FailedTests += Test_ChaCha_RoundFuncs();

    FailedTests += Test_ChaCha_Encrypt_Block();
    FailedTests += Test_ChaCha_Decrypt_Block();

    return FailedTests;
}

#endif
