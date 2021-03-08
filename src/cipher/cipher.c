/*
    Standard Library Headers
*/
#include <stdlib.h>
#include <string.h>

/*
    Local Library Headers
*/
#include "../AES/include/AES.h"
#include "../ChaCha/include/ChaCha.h"
#include "include/cipher.h"

/*
    Private Definitions
*/

/*
    Public Function Implementations
*/

Cipher_t *
Cipher_Prepare(Cipher_Algo_t Algorithm, Cipher_Mode_t Mode, const void *Key, const void *IV) {

    Cipher_t *Cipher = NULL;

    if (NULL == Key) {
        return NULL;
    }

    Cipher = (Cipher_t *)calloc(1, sizeof(Cipher_t));
    if (NULL == Cipher) {
        return NULL;
    }

    Cipher->Algorithm = Algorithm;

    /*
        Perform a dispatch to create the algorithm-specific cipher.
        It's less complex to just let each cipher algorithm set the fields and
        interpretations of them that it needs, rather than doing everything
        generically here.
    */
    switch (Cipher->Algorithm) {
    case AES_128:
        Cipher = Cipher_Prepare_AES(Cipher, AES_Key_128, Mode, Key, IV);
        break;
    case AES_192:
        Cipher = Cipher_Prepare_AES(Cipher, AES_Key_192, Mode, Key, IV);
        break;
    case AES_256:
        Cipher = Cipher_Prepare_AES(Cipher, AES_Key_256, Mode, Key, IV);
        break;
    case ChaCha20:
        Cipher = Cipher_Prepare_ChaCha(Cipher, Key, IV);
        break;
    case ALGO_NONE:
        Cipher_Release(Cipher);
        return NULL;
    }

    return Cipher;
}

Cipher_t *Cipher_Prepare_AES(Cipher_t *Cipher,
                             AES_Key_Length_t KeyLength,
                             Cipher_Mode_t Mode,
                             const void *Key,
                             const void *IV) {

    void *InitVector;
    Cipher->Mode = Mode;

    Cipher->Context = AES_Context_Prepare(AES_Block_128, KeyLength, Key);
    if (NULL == Cipher->Context) {
        Cipher_Release(Cipher);
        return NULL;
    }

    Cipher->FreeContext = (void (*)(void *))AES_Context_Release;
    Cipher->BlockLength = (size_t(*)(void *))AES_BlockLength;
    Cipher->Encrypt = (EncryptFunc)AES_Encrypt_Block;
    Cipher->Decrypt = (DecryptFunc)AES_Decrypt_Block;
    Cipher->IncrementCounter = (CounterIncFunc)AES_Counter_Increment;

    switch (Cipher->Mode) {
    case Cipher_Mode_NONE:
    case Cipher_Mode_ECB:
        break;
    case Cipher_Mode_CBC:
    case Cipher_Mode_CFB:
    case Cipher_Mode_OFB:
    case Cipher_Mode_CTR:
        Cipher->IV_Length = Cipher->BlockLength(Cipher->Context);
        Cipher->E_IV = (uint8_t *)calloc(Cipher->IV_Length, sizeof(uint8_t));
        if (NULL == Cipher->E_IV) {
            Cipher_Release(Cipher);
            return NULL;
        }

        Cipher->D_IV = (uint8_t *)calloc(Cipher->IV_Length, sizeof(uint8_t));
        if (NULL == Cipher->D_IV) {
            Cipher_Release(Cipher);
            return NULL;
        }

        if (NULL == IV) {
            InitVector = GenerateRandomVector(Cipher->IV_Length);
            memcpy(Cipher->E_IV, InitVector, Cipher->IV_Length);
            memcpy(Cipher->D_IV, InitVector, Cipher->IV_Length);
            free(InitVector);
        } else {
            memcpy(Cipher->E_IV, IV, Cipher->IV_Length);
            memcpy(Cipher->D_IV, IV, Cipher->IV_Length);
        }
        break;
    }

    Cipher->SpareBlock = (uint8_t *)calloc(Cipher->BlockLength(Cipher->Context), sizeof(uint8_t));
    if (NULL == Cipher->SpareBlock) {
        Cipher_Release(Cipher);
        return NULL;
    }

    return Cipher;
}

Cipher_t *Cipher_Prepare_ChaCha(Cipher_t *Cipher, const void *Key, const void *IV) {

    void *InitVector;
    const uint32_t *Counter;
    const uint32_t *Nonce;

    Cipher->Mode = Cipher_Mode_NONE;

    if (NULL == IV) {
        InitVector = GenerateRandomVector(ChaCha_Block_512 * sizeof(uint32_t));
        (*(uint32_t *)InitVector) = 1;
        Counter = (const uint32_t *)InitVector;
        Nonce = &(Counter[1]);
        Cipher->Context = ChaCha_Context_Prepare(Key, Nonce, Counter);
        free((void *)InitVector);
    } else {
        Counter = (const uint32_t *)IV;
        Nonce = &(Counter[1]);
        Cipher->Context = ChaCha_Context_Prepare(Key, Nonce, Counter);
    }

    if (NULL == Cipher->Context) {
        Cipher_Release(Cipher);
        return NULL;
    }

    Cipher->FreeContext = (void (*)(void *))ChaCha_Context_Release;
    Cipher->BlockLength = (size_t(*)(void *))ChaCha_Block_Length;
    Cipher->Encrypt = (EncryptFunc)ChaCha_Encrypt_Block;
    Cipher->Decrypt = (DecryptFunc)ChaCha_Decrypt_Block;
    Cipher->IncrementCounter = NULL;
    Cipher->E_IV = NULL;
    Cipher->D_IV = NULL;
    Cipher->IV_Length = 0;
    Cipher->SpareBlock = NULL;

    return Cipher;
}

ssize_t
Cipher_Encrypt(Cipher_t *Cipher, const void *Plaintext, size_t Length, uint8_t *Ciphertext) {

    /* Handle NULL pointers as errors. */
    if ((NULL == Cipher) || (NULL == Plaintext) || (NULL == Ciphertext)) {
        return -1;
    }

    /* A zero-length operation is fine, just do nothing. */
    if (0 == Length) {
        return 0;
    }

    switch (Cipher->Algorithm) {
    case AES_128:
    case AES_192:
    case AES_256:
        switch (Cipher->Mode) {
        case Cipher_Mode_ECB:
            return Cipher_Encrypt_AES_ECB(Cipher, Plaintext, Length, Ciphertext);
        case Cipher_Mode_CBC:
            return Cipher_Encrypt_AES_CBC(Cipher, Plaintext, Length, Ciphertext);
        case Cipher_Mode_CFB:
            return Cipher_Encrypt_AES_CFB(Cipher, Plaintext, Length, Ciphertext);
        case Cipher_Mode_OFB:
            return Cipher_Encrypt_AES_OFB(Cipher, Plaintext, Length, Ciphertext);
        case Cipher_Mode_CTR:
            return Cipher_Encrypt_AES_CTR(Cipher, Plaintext, Length, Ciphertext);
        case Cipher_Mode_NONE:
            return -1;
        }
        break;
    case ChaCha20:
        return Cipher_Encrypt_ChaCha(Cipher, Plaintext, Length, Ciphertext);
    case ALGO_NONE:
        return -1;
    }

    return -1;
}

ssize_t
Cipher_Decrypt(Cipher_t *Cipher, const void *Ciphertext, size_t Length, uint8_t *Plaintext) {

    /* Handle NULL pointers as errors. */
    if ((NULL == Cipher) || (NULL == Plaintext) || (NULL == Ciphertext)) {
        return -1;
    }

    /* A zero-length operation is fine, just do nothing. */
    if (0 == Length) {
        return 0;
    }

    switch (Cipher->Algorithm) {
    case AES_128:
    case AES_192:
    case AES_256:
        switch (Cipher->Mode) {
        case Cipher_Mode_ECB:
            return Cipher_Decrypt_AES_ECB(Cipher, Ciphertext, Length, Plaintext);
        case Cipher_Mode_CBC:
            return Cipher_Decrypt_AES_CBC(Cipher, Ciphertext, Length, Plaintext);
        case Cipher_Mode_CFB:
            return Cipher_Decrypt_AES_CFB(Cipher, Ciphertext, Length, Plaintext);
        case Cipher_Mode_OFB:
            return Cipher_Decrypt_AES_OFB(Cipher, Ciphertext, Length, Plaintext);
        case Cipher_Mode_CTR:
            return Cipher_Decrypt_AES_CTR(Cipher, Ciphertext, Length, Plaintext);
        case Cipher_Mode_NONE:
            return -1;
        }
        break;
    case ChaCha20:
        return Cipher_Decrypt_ChaCha(Cipher, Ciphertext, Length, Plaintext);
    case ALGO_NONE:
        return 1;
    }

    return 1;
}

void Cipher_Release(Cipher_t *Cipher) {

    size_t BlockSize = 0;

    if (NULL == Cipher) {
        return;
    }

    if (NULL != Cipher->BlockLength) {
        BlockSize = Cipher->BlockLength(Cipher->Context);
        if (NULL != Cipher->SpareBlock) {
            if (0 != BlockSize) {
                memset(Cipher->SpareBlock, 0x00, BlockSize);
            }
            free(Cipher->SpareBlock);
        }
    }
    Cipher->SpareBlock = NULL;
    Cipher->BlockLength = NULL;

    if (NULL != Cipher->FreeContext) {
        Cipher->FreeContext((void *)(Cipher->Context));
        Cipher->FreeContext = NULL;
        Cipher->Context = NULL;
    }

    if (NULL != Cipher->D_IV) {
        memset(Cipher->D_IV, 0x00, Cipher->IV_Length);
        free(Cipher->D_IV);
        Cipher->D_IV = NULL;
    }

    if (NULL != Cipher->E_IV) {
        memset(Cipher->E_IV, 0x00, Cipher->IV_Length);
        free(Cipher->E_IV);
        Cipher->E_IV = NULL;
    }

    Cipher->Encrypt = NULL;
    Cipher->Decrypt = NULL;
    Cipher->IncrementCounter = NULL;

    free(Cipher);

    return;
}

int Cipher_Update_IV(Cipher_t *Cipher, const void *IV) {

    if ((NULL == Cipher) || (NULL == IV)) {
        return 1;
    }

    switch (Cipher->Algorithm) {
    case AES_128:
    case AES_192:
    case AES_256:
        return Cipher_Update_IV_AES(Cipher, IV);
    case ChaCha20:
        return Cipher_Update_IV_ChaCha(Cipher, IV);
    case ALGO_NONE:
        return 1;
    }

    return 1;
}

int Cipher_Update_IV_AES(Cipher_t *Cipher, const void *IV) {

    if ((NULL == Cipher->E_IV) || (NULL == Cipher->D_IV)) {
        return 1;
    }

    memcpy(Cipher->E_IV, IV, Cipher->IV_Length);
    memcpy(Cipher->D_IV, IV, Cipher->IV_Length);

    return 0;
}

int Cipher_Update_IV_ChaCha(Cipher_t *Cipher, const void *IV) {

    const uint32_t *Counter = (const uint32_t *)IV;
    const uint32_t *Nonce = &(((const uint32_t *)IV)[CHACHA_COUNTER_LENGTH]);
    ChaCha_Context_t *Context = Cipher->Context;

    if (NULL == Context) {
        return 1;
    }

    if ((NULL == Context->D_Counter) || (NULL == Context->E_Counter) || (NULL == Context->Nonce)) {
        return 1;
    }

    memcpy(Context->D_Counter, Counter, CHACHA_COUNTER_LENGTH * sizeof(uint32_t));
    memcpy(Context->E_Counter, Counter, CHACHA_COUNTER_LENGTH * sizeof(uint32_t));
    memcpy(Context->Nonce, Nonce, CHACHA_NONCE_LENGTH * sizeof(uint32_t));

    return 0;
}

void *GenerateRandomVector(size_t Length) {

    size_t Index;

    void *Vector = malloc(Length);
    for (Index = 0; Index < Length; Index++) {
        ((uint8_t *)Vector)[Index] = (uint8_t)(rand() % (1 << 8));
    }

    return Vector;
}
