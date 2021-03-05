#ifndef LIBCRYPTO_CHACHA_ROUND_TEST_H
#define LIBCRYPTO_CHACHA_ROUND_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

int Test_ChaCha_RoundFuncs(void);

int Test_ChaCha_Rounds(void);
int Test_ChaCha_QuarterRound(void);
int Test_ChaCha_Rotate_Left(void);

#ifdef __cplusplus
}
#endif

#endif
