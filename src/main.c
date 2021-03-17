/*
    This file is simply the entry-point for testing and debugging of the
    library. This will execute the exposed top-level testing function
    for the full library, returning the number of failed tests back to
    the shell.
*/
#include <stdio.h>

#if defined(TESTING) || defined(DEBUGGER)

#include "../src/AES/include/AES.h"
#include "../src/ChaCha/include/ChaCha.h"
#include "../src/cipher/include/cipher.h"

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

    /*
        This little block is only here to suppress compiler warnings/errors
        for unused parameters. We want these errors for compiling everything
        except this file, so it's easiest to just echo this back to suppress
        these errors in a reasonable way.
    */
    int i;
    printf("Executing testing stub: %s", argv[0]);
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
    return 0;
#endif
}
