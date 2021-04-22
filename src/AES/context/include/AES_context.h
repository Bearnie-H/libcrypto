#ifndef LIBCRYPTO_AES_CONTEXT_H
#define LIBCRYPTO_AES_CONTEXT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <sys/types.h>

#include "../../include/AES_constants.h"

/*
    AES_Context_t

    The AES-specific context object to group the set of algorithm-specific
    parameters, state, and key schedule. This abstracts away and generalizes
    some of the algorithm values, generalizing them based on values of this
    context object.
*/
typedef struct AES_Context_t {

    /*
        The current internal encryption state.
        Received a copy of the block to encrypt,
        and is reset to 0's after each encryption
        or decryption operation.
    */
    uint8_t *State;

    /*
        Expanded Key schedule to use.
    */
    uint32_t *RoundKeys;

    /*  Number of 32-bit words in the key schedule */
    size_t RoundKeyLength;

    /*
        The number of 32-bit words in the block. By definition,
        AES requires this to be 4. This is parameterized in the
        rare case this ever changes.
    */
    AES_Block_Length_t BlockLength;

    /*
        The number of 32-bit words in the raw key
    */
    AES_Key_Length_t KeyWords;

    /*
        How many AES Rounds should be performed
    */
    AES_Round_Count_t NumRounds;

} AES_Context_t;

/*
    AES_Context_Prepare

    This function will prepare and initialize an AES_Context_t for use with
    the block size and key. Block Length is constant for AES as of the writing
    of this library.

    Inputs:
    BlockLength -   The number of 32-bit words in the cipher block
    KeyLength   -   The number of 32-bit words in the key
    Key         -   The raw bytes of key data to use

    Outputs:
    AES_Context_t*  -   Pointer to a ready-to-use AES_Context_t*, or NULL on error.

*/
AES_Context_t *
AES_Context_Prepare(AES_Block_Length_t BlockLength, AES_Key_Length_t KeyLength, const void *Key);

/*
    AES_KeyExpansion

    This function will generate the AES Round Key Schedule from the given key,
    writing the expanded bytes to the value pointed to by KeySchedule.

    Inputs:
    Key                 -   The raw key bytes to work with
    KeyWords            -   The number of 32-bit words in the key
    KeySchedule         -   Pointer to where to write the expanded keys to
    KeyScheduleLength   -   The number of 32-bit words in the expanded key schedule

    Outputs:
    int -   Returns 0 on success, nonzero on failure or error.

*/
int AES_KeyExpansion(const void *Key,
                     size_t KeyWords,
                     uint32_t *KeySchedule,
                     size_t KeyScheduleLength);

/*
    AES_BlockLength

    This function is a basic getter to allow the Cipher_t holding this
    Context to query the size of the block.

    Inputs:
    Ctx -   Pointer to the current context.

    Outputs:
    size_t  -   The size of the block used by this cipher, measured in 8-bit bytes.

*/
size_t AES_BlockLength(AES_Context_t *Ctx);

/*
    AES_Context_Release

    This function will safely release the Context, clearing all key
    and encryption data, and freeing all held resources.

    Inputs:
    Ctx -   Pointer to the Context to release

    Outputs:
    None, the given Context is freed and can no longer be used.

*/
void AES_Context_Release(AES_Context_t *Ctx);

/*
    SubWord

    This function will perform the AES S-Box substitution on each of the
    4 bytes of the given word, returning the substituted word. This is used
    during the key expansion stage of initializing an AES_Context_t.

    Inputs:
    Word        -   32-bit word to perform the substitution on.

    Outputs:
    uint32_t    -   32-bit word where each byte has been substituted using the
                    AES S-box.

*/
uint32_t SubWord(uint32_t Word);

/*
    RotWord

    This function will perform a 1-byte cyclic shift of the given
    32-bit word. This is used during the key expansion stage of initializing an
    AES_Context_t.

    Inputs:
    Word        -   The 32-bit word to perform the shift on.

    Outputs:
    uint32_t    -   32-bit word containing the cyclically shifted results.

*/
uint32_t RotWord(uint32_t Word);

#if defined(TESTING) || defined(DEBUGGER)

#include "AES_context_test.h"

#endif

#ifdef __cplusplus
}
#endif

#endif
