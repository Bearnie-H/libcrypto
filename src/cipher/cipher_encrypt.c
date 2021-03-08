#include <string.h>

#include "include/cipher.h"

/*
    All input argument validation has been performed before these function are called.
*/

ssize_t Cipher_Encrypt_AES_ECB(Cipher_t *Cipher,
                               const void *Plaintext,
                               size_t Length,
                               uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    const uint8_t *In = (const uint8_t *)Plaintext;

    /*
        While the remaining amount of data to encrypt is at least one block in length,
        just do the encryption and push out the requested block.
    */
    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, In, BlockBytes, Ciphertext)) {
            return -1;
        }

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    /*
        If there's a final partial block, zero-pad and push out the result.
    */
    memset(Cipher->SpareBlock, 0x00, BlockBytes);
    memcpy(Cipher->SpareBlock, Plaintext, Length);
    BytesWritten += Length;

    if (0 != Cipher->Encrypt(Cipher->Context, Cipher->SpareBlock, Length, Ciphertext)) {
        return -1;
    }

    BytesWritten += Length;

    return BytesWritten;
}

ssize_t Cipher_Encrypt_AES_CBC(Cipher_t *Cipher,
                               const void *Plaintext,
                               size_t Length,
                               uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->E_IV;
    const uint8_t *In = (const uint8_t *)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        BlockXOR(IV, In, BlockBytes);
        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
            return -1;
        }

        memcpy(Ciphertext, IV, BlockBytes);

        BytesWritten += BlockBytes;
        Ciphertext += BlockBytes;
        In += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    memset(&(IV[Length]), 0x00, BlockBytes - Length);
    BlockXOR(IV, In, Length);
    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
        return -1;
    }
    memcpy(Ciphertext, IV, BlockBytes);

    BytesWritten += BlockBytes;

    return BytesWritten;
}

ssize_t Cipher_Encrypt_AES_CFB(Cipher_t *Cipher,
                               const void *Plaintext,
                               size_t Length,
                               uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->E_IV;
    const uint8_t *In = (const uint8_t *)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return -1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(IV, Cipher->SpareBlock, BlockBytes);
        memcpy(Ciphertext, Cipher->SpareBlock, BlockBytes);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return -1;
    }

    BlockXOR(Cipher->SpareBlock, In, Length);
    memcpy(IV, Cipher->SpareBlock, BlockBytes);
    memcpy(Ciphertext, Cipher->SpareBlock, Length);
    memset(Cipher->SpareBlock, 0x00, BlockBytes);

    BytesWritten += Length;

    return BytesWritten;
}

ssize_t Cipher_Encrypt_AES_OFB(Cipher_t *Cipher,
                               const void *Plaintext,
                               size_t Length,
                               uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->E_IV;
    const uint8_t *In = (const uint8_t *)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
            return -1;
        }

        memcpy(Cipher->SpareBlock, IV, BlockBytes);
        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Ciphertext, Cipher->SpareBlock, BlockBytes);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV)) {
        return -1;
    }

    memcpy(Cipher->SpareBlock, IV, BlockBytes);
    BlockXOR(Cipher->SpareBlock, In, Length);
    memcpy(Ciphertext, Cipher->SpareBlock, Length);
    memset(Cipher->SpareBlock, 0x00, BlockBytes);

    BytesWritten += Length;

    return BytesWritten;
}

ssize_t Cipher_Encrypt_AES_CTR(Cipher_t *Cipher,
                               const void *Plaintext,
                               size_t Length,
                               uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    uint8_t *IV = Cipher->E_IV;
    const uint8_t *In = (const uint8_t *)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
            return -1;
        }

        BlockXOR(Cipher->SpareBlock, In, BlockBytes);
        memcpy(Ciphertext, Cipher->SpareBlock, BlockBytes);

        Cipher->IncrementCounter(IV);

        BytesWritten += BlockBytes;
        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock)) {
        return -1;
    }

    BlockXOR(Cipher->SpareBlock, In, Length);
    memcpy(Ciphertext, Cipher->SpareBlock, Length);

    BytesWritten += Length;

    Cipher->IncrementCounter(IV);

    return BytesWritten;
}

ssize_t
Cipher_Encrypt_ChaCha(Cipher_t *Cipher, const void *Plaintext, size_t Length, uint8_t *Ciphertext) {

    ssize_t BytesWritten = 0;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    size_t Index = 0;
    const uint8_t *In = (const uint8_t *)Plaintext;
    uint8_t *Out = (uint8_t *)Ciphertext;

    while (Length >= BlockBytes) {

        if (0 != Cipher->Encrypt(Cipher->Context, &(In[Index]), BlockBytes, &(Out[Index]))) {
            return -1;
        }

        BytesWritten += BlockBytes;
        Index += BlockBytes;
        Length -= BlockBytes;
    }

    if (0 == Length) {
        return BytesWritten;
    }

    if (0 != Cipher->Encrypt(Cipher->Context, &(In[Index]), Length, &(Out[Index]))) {
        return -1;
    }

    BytesWritten += Length;

    return BytesWritten;
}
