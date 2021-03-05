#include <string.h>

#include "include/cipher.h"

/*
    All input argument validation has been performed before these function are called.
*/

int Cipher_Decrypt_AES_ECB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext) {

    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    const uint8_t *In = (const uint8_t *)Ciphertext;

    /*
        Basically the same as Cipher_Encrypt_ECB(), but using the Decrypt function,
        and we know the Length is a guaranteed multiple of the block size.
    */

    while (Length != 0) {

        if (0 != Cipher->Decrypt(Cipher->Context, In, BlockBytes, Plaintext)) {
            return 1;
        }

        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    return 0;
}

int Cipher_Decrypt_AES_CBC(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext) {

    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Decrypt(Cipher->Context, In, BlockBytes, Cipher->SpareBlock)) {
            return 1;
        }

        BlockXOR(Cipher->SpareBlock, IV, BlockBytes);
        memcpy(IV, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    memset(Cipher->SpareBlock, 0x00, BlockBytes);

    return 0;
}

int Cipher_Decrypt_AES_CFB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext) {

    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return 1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(IV, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return 0;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return 1;
    }

    memcpy(Plaintext, Cipher->SpareBlock, Length);
    memset(Cipher->SpareBlock, 0x00, BlockBytes);
    BlockXOR(Plaintext, In, Length);

    return 0;
}

int Cipher_Decrypt_AES_OFB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext) {

    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
            return 1;
        }

        memcpy(Cipher->SpareBlock, IV, BlockBytes);
        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return 0;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
        return 1;
    }

    memcpy(Cipher->SpareBlock, IV, BlockBytes);
    BlockXOR(Cipher->SpareBlock, In, BlockBytes);
    memcpy(Plaintext, Cipher->SpareBlock, Length);

    return 1;
}

int Cipher_Decrypt_AES_CTR(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext) {

    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return 1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        Cipher->IncrementCounter(IV);

        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return 0;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return 1;
    }

    BlockXOR(Cipher->SpareBlock, In, Length);
    memcpy(Plaintext, Cipher->SpareBlock, Length);
    Cipher->IncrementCounter(IV);

    return 0;
}

int Cipher_Decrypt_ChaCha(Cipher_t *Cipher,
                          const void *Ciphertext,
                          size_t Length,
                          uint8_t *Plaintext) {

    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    size_t Index = 0;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    uint8_t *Out = (uint8_t *)Plaintext;

    while (Length >= BlockBytes) {

        if (0 != Cipher->Decrypt(Cipher->Context, &(In[Index]), BlockBytes, &(Out[Index]))) {
            return 1;
        }
        Index += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return 0;
    }

    if (0 != Cipher->Decrypt(Cipher->Context, &(In[Index]), Length, &(Out[Index]))) {
        return 1;
    }

    return 0;
}
