#include <string.h>

#include "include/cipher.h"

/*
    All input argument validation has been performed before these function are called.
*/

int Cipher_Encrypt_AES_ECB(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    const uint8_t* In = (const uint8_t*)Plaintext;

    /*
        While the remaining amount of data to encrypt is at least one block in length,
        just do the encryption and push out the requested block.
    */
    while ( Length >= BlockBytes ) {

        if ( 0 != Cipher->Encrypt(Cipher->Context, In, BlockBytes, Ciphertext) ) {
            return 1;
        }

        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    /*
        If there's a final partial block, zero-pad and push out the result.
    */
    memset(Cipher->SpareBlock, 0x00, BlockBytes);
    memcpy(Cipher->SpareBlock, Plaintext, Length);
    
    return Cipher->Encrypt(Cipher->Context, Cipher->SpareBlock, Length, Ciphertext);
}

int Cipher_Encrypt_AES_CBC(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    uint8_t* IV = Cipher->E_IV;
    const uint8_t* In = (const uint8_t*)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while ( Length >= BlockBytes ) {

        BlockXOR(IV, In, BlockBytes);
        if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV) ) {
            return 1;
        }

        memcpy(Ciphertext, IV, BlockBytes);
        Ciphertext += BlockBytes;
        In += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    memset(&(IV[Length]), 0x00, BlockBytes - Length);
    BlockXOR(IV, In, Length);
    if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV) ) {
        return 1;
    }
    memcpy(Ciphertext, IV, BlockBytes);
    
    return 0;
}

int Cipher_Encrypt_AES_CFB(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    uint8_t* IV = Cipher->E_IV;
    const uint8_t* In = (const uint8_t*)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while ( Length >= BlockBytes ) {

        if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Ciphertext) ) {
            return 1;
        }

        BlockXOR(Ciphertext, In, BlockBytes);
        memcpy(IV, Ciphertext, BlockBytes);

        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock) ) {
        return 1;
    }

    memcpy(Ciphertext, Cipher->SpareBlock, Length);
    memset(Cipher->SpareBlock, 0x00, BlockBytes);
    BlockXOR(Ciphertext, In, Length);

    return 0;
}

int Cipher_Encrypt_AES_OFB(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    uint8_t* IV = Cipher->E_IV;
    const uint8_t* In = (const uint8_t*)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while ( Length >= BlockBytes ) {

        if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV) ) {
            return 1;
        }

        memcpy(Ciphertext, IV, BlockBytes);
        BlockXOR(Ciphertext, In, BlockBytes);

        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, IV) ) {
        return 1;
    }
    memcpy(Ciphertext, IV, Length);
    BlockXOR(Ciphertext, In, Length);
    
    return 1;
}

int Cipher_Encrypt_AES_CTR(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    uint8_t* IV = Cipher->E_IV;
    const uint8_t* In = (const uint8_t*)Plaintext;
    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);

    while ( Length >= BlockBytes ) {

        if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Ciphertext) ) {
            return 1;
        }

        BlockXOR(Ciphertext, In, BlockBytes);
        Cipher->IncrementCounter(IV);

        In += BlockBytes;
        Ciphertext += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    if ( 0 != Cipher->Encrypt(Cipher->Context, IV, BlockBytes, Cipher->SpareBlock) ) {
        return 1;
    }

    memcpy(Ciphertext, Cipher->SpareBlock, Length);
    BlockXOR(Ciphertext, In, Length);
    Cipher->IncrementCounter(IV);
    
    return 0;
}

int Cipher_Encrypt_ChaCha(Cipher_t* Cipher, const void* Plaintext, size_t Length, uint8_t* Ciphertext) {

    size_t BlockBytes = Cipher->BlockLength(Cipher->Context);
    size_t Index = 0;
    const uint8_t* In = (const uint8_t*)Plaintext;
    uint8_t* Out = (uint8_t*)Ciphertext;

    while ( Length >= BlockBytes ) {

        if ( 0 != Cipher->Encrypt(Cipher->Context, &(In[Index]), BlockBytes, &(Out[Index])) ) {
            return 1;
        }
        Index += BlockBytes;
        Length -= BlockBytes;
    }

    if ( 0 == Length ) {
        return 0;
    }

    if ( 0 != Cipher->Encrypt(Cipher->Context, &(In[Index]), Length, &(Out[Index])) ) {
        return 1;
    }

    return 0;
}
