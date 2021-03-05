#include <stdio.h>

#include "../include/libcrypto.h"

#if defined(TESTING) || defined(DEBUGGER)

int Test_Libcrypto(void) {

    int FailedTests = 0;

    FailedTests += Test_AES();
    FailedTests += Test_ChaCha();
    FailedTests += Test_Cipher();

    if (0 == FailedTests) {
        printf("Libcrypto: Successfully passed all internal self-tests!\n");
    } else {
        printf("Libcrypto: Internal self-tests failed. Review error messages and correct these "
               "immediately!\n");
    }

    return FailedTests;
}

#endif

int main(int argc, char **argv) {

    int i;

    printf("Executing: %s", argv[0]);
    for (i = 1; i < argc; i++) {
        printf(" %s", argv[i]);
    }
    printf("\n");

    /*
        If the executable is built in Test-mode, call the main testing function.
    */
#if defined(TESTING) || defined(DEBUGGER)
    return Test_Libcrypto();
#else

    /*
        Otherwise, do the standard application logic.
    */

    /* ... */

    return 0;
#endif
}
