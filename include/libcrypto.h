/*
    Libcrypto

    This is an academic implementation of a selectable block or stream cipher,
    based on either AES (Rijndael), or the ChaCha encryption algorithms.

    This library provides a correct implementation of these ciphers,
    but this is not suitable for production systems, as only minimal
    effort has been put towards addressing side-channel or timing
    attacks. This library only guarantees algorithmic correctness.
*/
#ifndef LIBCRYPTO_H
#define LIBCRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

/*
    Required Standard Library Headers
*/
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/*
    Cipher_t

    An opaque structure which implements either a stream or block cipher.
    This should be treated as a black box, with the functions from this
    library used to operate on it.
*/
typedef struct Cipher_t Cipher_t;

/*
    Cipher_Mode_t

    The "mode of operation" to use the cipher in. This defines
    how the cipher should handle input messages which are not exactly
    one block long of the underlying block cipher.
*/
typedef enum Cipher_Mode_t {

    /*
        If the Cipher_Algo_t implies only one valid mode of operation,
        this lets it be "ignored".
    */
    Cipher_Mode_NONE,

    /*
        Electronic Code Book mode.

        Provided IV is not used, and NULL may be passed.
    */
    Cipher_Mode_ECB,

    /*
        Cipher Block Chaining mode.

        IV must be equal to one block of data. Used as a Nonce.
    */
    Cipher_Mode_CBC,

    /*
        Cipher Feedback mode.

        IV must be equal to one block of data. Used as the initial
        encryption input to generate the keystream.
    */
    Cipher_Mode_CFB,

    /*
        Output Feedback mode.

        IV must be equal to one block of data. Used as the initial
        encryption input to generate the keystream.
    */
    Cipher_Mode_OFB,

    /*
        Counter mode.

        IV must be equal to one block of data.
        Consists of a Nonce and a Counter subsection.

        For AES, the first 64-bits correspond to the counter and
        the latter 64-bits correspond to the Nonce.
    */
    Cipher_Mode_CTR

    /* Additional Modes below... */

} Cipher_Mode_t;

/*
    Cipher_Algo_t

    Which underlying block-cipher algorithm to use.
    This modifies how the IV value is interpreted. See the
    specific options below for a description of how.
*/
typedef enum Cipher_Algo_t {

    /*
        Default value for a "nothing" value.
    */
    ALGO_NONE,

    AES_128, /* AES with a 128-bit Key. IV interpreted based on Cipher_Mode_t. */
    AES_192, /* AES with a 192-bit Key. IV interpreted based on Cipher_Mode_t. */
    AES_256, /* AES with a 256-bit Key. IV interpreted based on Cipher_Mode_t. */

    /*
        ChaCha with 20 rounds.

        The IV for this Cipher Algorithm must be a
        4 x 32-bit value. The first 32 bits will be treated
        as the "Block Index", and the remaining bits used as a Nonce.
    */
    ChaCha20

    /* Additional Algorithms below... */

} Cipher_Algo_t;

/*
    Public Interface Functions
*/

/*
    Cipher_Prepare

    This function will prepare a new Cipher_t object for use. It will use the specified
    encryption algorithm, in the specified mode, using the given Key. The value pointed
    to by "Key" will have a number of bytes read depending on the key length specified
    by the selected Algorithm.

    The value chosen for the IV is interpreted differently based on the specific
    Algorithm and Mode selected. See the descriptions of the options for
    Cipher_Algorithm_t and Cipher_Mode_t for a description of how the IV
    will be interpreted.

    Inputs:
    Algorithm   -   The specific encryption algorithm to use in the Cipher.
    Mode        -   The mode of operation to use for multi-block encryption.
    Key         -   The raw key bytes to use in the cipher.
    IV          -   The raw bytes to use as the IV. (Mode specific)

    Outputs:
    Cipher_t*   -   NULL on error, otherwise a fully prepared and ready-to-use
                    Cipher_t object to be used with the Cipher_Encrypt() or
                    Cipher_Decrypt() functions.
*/
Cipher_t *
Cipher_Prepare(Cipher_Algo_t Algorithm, Cipher_Mode_t Mode, const void *Key, const void *IV);

/*
    Cipher_Update_IV

    This function allows updating of the Initialization Vector (IV) to be used
    by the Cipher. How this vector is interpreted differs based on both the mode
    of operation, and the specific algorithm used. See the descriptions provided
    on the options for the Cipher_Algo_t and Cipher_Mode_t types for more information.

    Inputs:
    Cipher  -   Pointer to the (at least partially) initialized Cipher object to update IVs for.
    IV      -   Pointer to the raw bytes to use as the new IV. This will overwrite any existing
                    value in the Cipher.

    Outputs:
    int -   Returns 0 on success, nonzero on failure or error.
*/
int Cipher_Update_IV(Cipher_t *Cipher, const void *IV);

/*
    Cipher_Encrypt

    This function will use the Cipher_t to encrypt the given Plaintext, which is 'Length' bytes
   long, writing the encrypted output to the value pointed to by Ciphertext. This uses the algorithm
    specified when the Cipher_t was prepared, as well as using the specified Mode.

    Inputs:
    Cipher      -   Pointer to a previously prepared Cipher_t object.
    Plaintext   -   Pointer to the raw plaintext to encrypt.
    Length      -   The length of the Plaintext, measured in 8-bit bytes.
    Ciphertext  -   Pointer to a location to write the encrypted ciphertext to.
                        The memory must be owned by the caller, and it must
                        be large enough to accept the fully encrypted output.

    Outputs:
    ssize_t         -   Returns the number of bytes written, or -1 on error
*/
ssize_t Cipher_Encrypt(Cipher_t *Cipher, const void *Plaintext, size_t Length, uint8_t *Ciphertext);

/*
    Cipher_Encrypt_Stream

    This function will use the Cipher_t to Encrypt the given stream,
    represented by the file descriptor fd_In, writing the resulting
    output to the file descriptor fd_Out. These may be any file descriptors
    capable of being operated on by the standard read() and write() calls.
    These file descriptors are not owned by this function, and must be
    opened and closed by the caller.

    This function will safely align blocks, such that intermediate reads will
    wait until one full block of data is ready, rather than padding partial
    blocks. Only the final block, if it does not evenly divide the block size,
    and the underlying cipher mode and algorithm imply block-operation, will be
    padded to fit.

    Inputs:
    Cipher  -   Pointer to the Cipher object to use.
    fd_In   -   File descriptor to read raw data from, using read().
    fd_Out  -   File descriptor to write resultant data to, using write().

    Outputs:
    ssize_t -   Returns -1 on errors, or the number of bytes successfully transferred.
*/
ssize_t Cipher_Encrypt_Stream(Cipher_t* Cipher, int fd_In, int fd_Out);

/*
    Cipher_Decrypt

    This function will use the Cipher_t to decrypt the given Ciphertext, which is 'Length' bytes
    long, writing the decrypted output to the value pointed to by Plaintext. This uses the algorithm
    specified when the Cipher_t was prepared, as well as using the specified Mode.

    Inputs:
    Cipher      -   Pointer to a previously prepared Cipher_t object.
    Ciphertext  -   Pointer to the raw Ciphertext to decrypt.
    Length      -   The length of the Ciphertext, measured in 8-bit bytes.
    Plaintext   -   Pointer to a location to write the decrypted Plaintext to.
                        The memory must be owned by the caller, and it must
                        be large enough to accept the fully encrypted output.

    Outputs:
    ssize_t         -   Returns the number of bytes written, or -1 on error
*/
ssize_t Cipher_Decrypt(Cipher_t *Cipher, const void *Ciphertext, size_t Length, uint8_t *Plaintext);

/*
    Cipher_Decrypt_Stream

    This function will use the Cipher_t to Decrypt the given stream,
    represented by the file descriptor fd_In, writing the resulting
    output to the file descriptor fd_Out. These may be any file descriptors
    capable of being operated on by the standard read() and write() calls.
    These file descriptors are not owned by this function, and must be
    opened and closed by the caller.

    This function will safely align blocks, such that intermediate reads will
    wait until one full block of data is ready, rather than padding partial
    blocks. Only the final block, if it does not evenly divide the block size,
    and the underlying cipher mode and algorithm imply block-operation, will be
    padded to fit.

    Inputs:
    Cipher  -   Pointer to the Cipher object to use.
    fd_In   -   File descriptor to read raw data from, using read().
    fd_Out  -   File descriptor to write resultant data to, using write().

    Outputs:
    ssize_t -   Returns -1 on errors, or the number of bytes successfully transferred.
*/
ssize_t Cipher_Decrypt_Stream(Cipher_t* Cipher, int fd_In, int fd_Out);

/*
    Cipher_Release

    This function will release the Cipher_t and all held resources. This will
    clear all fields of the structure.

    Inputs:
    Cipher  -   Pointer to a previously prepared Cipher_t object.

    Outputs:
    void    -   The Cipher_t and all held resources are safely released.
*/
void Cipher_Release(Cipher_t *Cipher);

#ifdef __cplusplus
}
#endif
#endif
