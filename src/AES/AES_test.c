#include <stdio.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "context/include/AES_context.h"
#include "include/AES.h"
#include "round/include/AES_round.h"

int Test_AES(void) {

    int FailedTests = 0;

    FailedTests += Test_AES_Context();
    FailedTests += Test_AES_RoundFuncs();

    FailedTests += Test_AES_Encrypt_Block();
    FailedTests += Test_AES_Decrypt_Block();

    return FailedTests;
}

#endif
