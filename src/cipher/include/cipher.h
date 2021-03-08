#ifndef LIBCRYPTO_CIPHER_H
#define LIBCRYPTO_CIPHER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../../include/libcrypto.h"
#include "../../AES/include/AES.h"

#define CIPHER_STREAM_BUFFER_SIZE ( 1 << 12 )
#define CIPHER_MIN_READ_SIZE ( 1 << 4 )

/*
    Function typedefs for use within the Cipher_t object.
*/
typedef int (*EncryptFunc)(void *, const void *, size_t, uint8_t *);
typedef int (*DecryptFunc)(void *, const void *, size_t, uint8_t *);

typedef void (*CounterIncFunc)(void *);

/*
    Cipher_t

    Internal definition of a Cipher_t object.
*/
struct Cipher_t {

    Cipher_Algo_t Algorithm;
    Cipher_Mode_t Mode;

    /*
        The 'Context' pointer will point to an algorithm-specific
        structure containing helpful additional fields and constants
        for the actual encryption itself.
    */
    void *Context;

    /*
        This contains the function pointer to the function which can
        safely release the resources held by the given Context object.
    */
    void (*FreeContext)(void *Context);

    /*
        Query the held context, returning the size of the block in bytes.
    */
    size_t (*BlockLength)(void *Context);

    /*
        Encryption and Decryption function pointers.

        These abstract out the specific algorithm behind
        a consistent interface. These take, in order:

            *_Context_t*    - Algorithm-specific context.
            void*           - Input bytes
            size_t          - Input length
            uint8_t*        - Output location

        These are initialized during Cipher_Prepare(),
        and will be called upon as the cipher-level primitives
        for encrypting a given block.
    */
    EncryptFunc Encrypt;
    DecryptFunc Decrypt;

    /*
        Initialization vectors for the encryption and decryption operations.
        These must be separate to allow for stream-resumption and time-asynchronous
        encryption and decryption.

        For modes of operation which do not use Initialization Vectors,
        these will be set to and remain NULL.

        The CounterIncFunc is used to update the IVs in either a Counter-type
        mode, or when using a Cipher Algorithm which only runs in a Counter-type mode.
    */
    CounterIncFunc IncrementCounter;
    uint8_t *E_IV;
    uint8_t *D_IV;
    size_t IV_Length;

    /*
        SpareBlock is a block of memory equal in size to one block of the underlying
        cipher, used as working space during multi-block operations.
    */
    uint8_t *SpareBlock;
};

/*
    Algorithm-specific Cipher Preparation Functions.

    This should simplify the process of initializing the Cipher_t
    for different underlying algorithms, as not all use or require the same
    features.
*/

Cipher_t *Cipher_Prepare_AES(Cipher_t *Cipher,
                             AES_Key_Length_t KeyLength,
                             Cipher_Mode_t Mode,
                             const void *Key,
                             const void *IV);

Cipher_t *Cipher_Prepare_ChaCha(Cipher_t *Cipher, const void *Key, const void *IV);

int Cipher_Update_IV_AES(Cipher_t *Cipher, const void *IV);
int Cipher_Update_IV_ChaCha(Cipher_t *Cipher, const void *IV);

/*
    Mode-of-operation specific function defintions.

    The public library function that's exposed simply checks arguments and then dispatches to
    one of these functions.
*/
ssize_t Cipher_Encrypt_AES_ECB(Cipher_t *Cipher,
                           const void *Plaintext,
                           size_t Length,
                           uint8_t *Ciphertext);
ssize_t Cipher_Encrypt_AES_CBC(Cipher_t *Cipher,
                           const void *Plaintext,
                           size_t Length,
                           uint8_t *Ciphertext);
ssize_t Cipher_Encrypt_AES_CFB(Cipher_t *Cipher,
                           const void *Plaintext,
                           size_t Length,
                           uint8_t *Ciphertext);
ssize_t Cipher_Encrypt_AES_OFB(Cipher_t *Cipher,
                           const void *Plaintext,
                           size_t Length,
                           uint8_t *Ciphertext);
ssize_t Cipher_Encrypt_AES_CTR(Cipher_t *Cipher,
                           const void *Plaintext,
                           size_t Length,
                           uint8_t *Ciphertext);
ssize_t Cipher_Encrypt_ChaCha(Cipher_t *Cipher,
                          const void *Plaintext,
                          size_t Length,
                          uint8_t *Ciphertext);

ssize_t Cipher_Decrypt_AES_ECB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext);
ssize_t Cipher_Decrypt_AES_CBC(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext);
ssize_t Cipher_Decrypt_AES_CFB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext);
ssize_t Cipher_Decrypt_AES_OFB(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext);
ssize_t Cipher_Decrypt_AES_CTR(Cipher_t *Cipher,
                           const void *Ciphertext,
                           size_t Length,
                           uint8_t *Plaintext);
ssize_t Cipher_Decrypt_ChaCha(Cipher_t *Cipher,
                          const void *Ciphertext,
                          size_t Length,
                          uint8_t *Plaintext);

/*
    Minor helper functions below
*/
void *GenerateRandomVector(size_t Length);

/*
    This will compute A = A ^ B where A and B are both
    'Length' bytes long.
*/
void BlockXOR(uint8_t *A, const uint8_t *B, size_t Length);

#if defined(TESTING) || defined(DEBUGGER)

#include "cipher_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
