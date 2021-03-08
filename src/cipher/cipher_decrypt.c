#include <string.h>

#include "include/cipher.h"

/*
    All input argument validation has been performed before these function are called.
*/

ssize_t Cipher_Decrypt_AES_ECB(Cipher_t *Cipher,
                               const void *Ciphertext,
                               size_t Length,
                               uint8_t *Plaintext) {

    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    ssize_t BytesWritten = 0;
    const uint8_t *In = (const uint8_t *)Ciphertext;

    /*
        Basically the same as Cipher_Encrypt_ECB(), but using the Decrypt function,
        and we know the Length is a guaranteed multiple of the block size.
    */

    while (Length != 0) {

        if (0 != Cipher->Decrypt(Cipher->Context, In, BlockBytes, Plaintext)) {
            return -1;
        }

        In += BlockBytes;
        Plaintext += BlockBytes;
        BytesWritten += BlockBytes;
        Length -= BlockBytes;
    }

    return BytesWritten;
}

ssize_t Cipher_Decrypt_AES_CBC(Cipher_t *Cipher,
                               const void *Ciphertext,
                               size_t Length,
                               uint8_t *Plaintext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Decrypt(Cipher->Context, In, BlockBytes, Cipher->SpareBlock)) {
            return -1;
        }

        BlockXOR(Cipher->SpareBlock, IV, BlockBytes);
        memcpy(IV, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    memset(Cipher->SpareBlock, 0x00, BlockBytes);

    return BytesWritten;
}

ssize_t Cipher_Decrypt_AES_CFB(Cipher_t *Cipher,
                               const void *Ciphertext,
                               size_t Length,
                               uint8_t *Plaintext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return -1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(IV, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return -1;
    }

    BytesWritten += Length;
    memcpy(Plaintext, Cipher->SpareBlock, Length);
    memset(Cipher->SpareBlock, 0x00, BlockBytes);
    BlockXOR(Plaintext, In, Length);

    return BytesWritten;
}

ssize_t Cipher_Decrypt_AES_OFB(Cipher_t *Cipher,
                               const void *Ciphertext,
                               size_t Length,
                               uint8_t *Plaintext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
            return -1;
        }

        memcpy(Cipher->SpareBlock, IV, BlockBytes);
        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
        return -1;
    }

    BytesWritten += Length;
    memcpy(Cipher->SpareBlock, IV, BlockBytes);
    BlockXOR(Cipher->SpareBlock, In, BlockBytes);
    memcpy(Plaintext, Cipher->SpareBlock, Length);

    return BytesWritten;
}

ssize_t Cipher_Decrypt_AES_CTR(Cipher_t *Cipher,
                               const void *Ciphertext,
                               size_t Length,
                               uint8_t *Plaintext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->D_IV;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return -1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Plaintext, Cipher->SpareBlock, BlockBytes);

        Cipher->IncrementCounter(IV);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Plaintext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return -1;
    }

    BlockXOR(Cipher->SpareBlock, In, Length);
    memcpy(Plaintext, Cipher->SpareBlock, Length);
    Cipher->IncrementCounter(IV);

    BytesWritten += Length;

    return BytesWritten;
}

ssize_t
Cipher_Decrypt_ChaCha(Cipher_t *Cipher, const void *Ciphertext, size_t Length, uint8_t *Plaintext) {

    ssize_t BytesWritten = 0;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    size_t Index = 0;
    const uint8_t *In = (const uint8_t *)Ciphertext;
    uint8_t *Out = (uint8_t *)Plaintext;

    while (Length >= BlockBytes) {

        if (0 != Cipher->Decrypt(Cipher->Context, &(In[Index]), BlockBytes, &(Out[Index]))) {
            return -1;
        }

        BytesWritten += BlockBytes;
        Index += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Decrypt(Cipher->Context, &(In[Index]), Length, &(Out[Index]))) {
        return -1;
    }

    BytesWritten += Length;

    return BytesWritten;
}
