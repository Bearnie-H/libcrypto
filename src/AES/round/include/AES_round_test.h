#ifndef LIBCRYPTO_AES_ROUND_TEST_H
#define LIBCRYPTO_AES_ROUND_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

int Test_AES_RoundFuncs(void);

int Test_AES_AddRoundKey(void);

int Test_AES_SubBytes(void);
int Test_AES_ShiftRows(void);
int Test_AES_MixColumns(void);

int Test_AES_InvSubBytes(void);
int Test_AES_InvShiftRows(void);
int Test_AES_InvMixColumns(void);

#ifdef __cplusplus
}
#endif

#endif
