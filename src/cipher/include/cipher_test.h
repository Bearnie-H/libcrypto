#ifndef LIBCRYPTO_CIPHER_TEST_H
#define LIBCRYPTO_CIPHER_TEST_H

#ifdef __cplusplus
extern "C" {
#endif

int Test_Cipher(void);

int Test_Cipher_Prepare(void);
int Test_Cipher_Prepare_AES(void);
int Test_Cipher_Prepare_ChaCha(void);

int Test_Cipher_Modes(void);

int Test_Cipher_AES_ECB(void);
int Test_Cipher_AES_CBC(void);
int Test_Cipher_AES_CFB(void);
int Test_Cipher_AES_OFB(void);
int Test_Cipher_AES_CTR(void);
int Test_Cipher_ChaCha(void);

#ifdef __cplusplus
}
#endif

#endif
