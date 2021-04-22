# libcrypto

This library contains an academic implementation of the
[Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf),
as well as the [ChaCha20](https://tools.ietf.org/html/rfc7539) ciphers. This does
not include any of the additional message authentication features typically
bundled with the ciphers.

This library is fully ANSI-C, and has been tested for portability over for both OS X,
and Linux, as well as ARM and x86. Endian-ness has not been tested for portability,
but this was not an important goal for this project.
# THIS LIBRARY SHOULD NOT BE USED IN PRODUCTION SOFTWARE

Part of the academic exploration of the ciphers this library aims to achieve is
an understanding of where and how attacks can present themselves in an
algorithmically secure cipher. The mathematics behind the ciphers provide certain
cryptographic guarantees in the domain of pure math, but the exact manner
of implementation may present pathways for an attacker to break the crypto-system
which are not present in the pure description.

Timing attacks and other side-channel attacks are almost certainly present
in this library. The only guarantee is that the ciphers as implemented are
algorithmically correct for both the block operations, and the multi-block
mode of operation functionality. Addressing these modes of attack typically
involves re-framing the algorithms in terms of pre-computed lookup tables and
esoteric-looking branch-free code. These have the great benefit of removing
avenues of attack, but at the cost of obfuscating the connection between
source code and the underlying mathematics.

# AES Implementation

This implementation is 
derived almost exactly from the original NIST specification. Only minor naming changes
were done to ensure a cleaner namespace within the library.

This implementation successfully covers the three key sizes used in AES: 128-bit,
192-bit, and 256-bit. It also successfully implements a number of instructive
multi-block modes of operation for the AES cipher specifically. The supported modes are
defined by the `Cipher_Mode_t` type.

The self-testing suite of the library references test vectors from the standards document
to demonstrate correctness of the internal round functions, as well as one-way encryption
and decryption. Round-trip correctness is tested and verified by reusing the same `Cipher_t`
to encrypt and decrypt a message, ensuring the output is bit-identical to the source.
This round-trip testing is also performed for the various multi-block modes of operation
to validate their operation.

As allowed by the standards, any remaining keystream bytes from a stream-cipher
mode will be **DISCARDED** at the end of a transaction. As a result, the concatenation
of two stream-cipher mode outputs **DOES NOT** guarantee to decrypt correctly,
except in the case where messages exactly divide into blocks.

# ChaCha20 Implementation

This implementation is derived closely from the RFC specification. Again, minor renaming
changes were done for namespace collision and internal library symbol management.

This algorithm was added to provide both an alternative to AES for cryptographic needs,
as well as demonstrating the simplicity and implicit removal of a number of side-channels
for attack when using an ARX (Add-Rotate-XOR) cipher. ChaCha entails a substantially simpler
implementation, with no necessary branching or decision pathways. It is also fully symmetric
between encryption and decryption, further simplifying the operation. Finally, it is
implicitly a stream-cipher operation, and does not require multi-block mode of operation
beyond what is specified by the default operation.

# Using the Library

This library provides a `Cipher_t` struct, as well as related `Cipher_Algo_t` and `Cipher_Mode_t`
types as the primary interface. The `Cipher_t` struct provides an opaque interface to
operate on either pre-allocated buffers (`Cipher_Encrypt()` and `Cipher_Decrypt()`),
or to operate on *streams* (file descriptors) (`Cipher_Encrypt_Stream()` and `Cipher_Decrypt_Stream()`).

Mixing between the two types of operation (buffer <-> stream) unfortunately necessitates
splitting up the read/write operations and the encrypt/decrypt operations. This is a possible
future extension to the library.

A `Cipher_t` must be prepared via the `Cipher_Prepare()` call. Pass in the Algorithm (`Cipher_Algo_t`),
Mode of Operation (`Cipher_Mode_t`), the Key, and the Nonce to use. The returned `Cipher_t` is
fully ready to use for arbitrary encryption or decryption tasks from that point on.
To safely release the `Cipher_t`, simply pass it to `Cipher_Release()`.

# Building the Library

This library was built and designed with the standard `Make` tool as the primary build
tool. There are a number of valuable targets to select from:

* test
    * This will build the library into a test executable, using the included src/main.c driver file
    to provide an entry point. This test executable will run the full internal test suite included
    within the library. The build target includes the execution of this test executable. If any tests
    fail, this will return non-zero and indicate to `Make` that it should also return an error.
    * This defines the macros `TESTING`, `DEBUGGER`, and `DEBUG`.

* debugger
    * This will build the library into an executable suitable for use with a standard debugger.
    This is very similar to the `test` target, with only a naming difference and that the macro
    "TESTING" is left undefined. This target does not execute the built executable.
    * This defines the macros `DEBUGGER`, and `DEBUG`.

* debug
    * This will build the library into a statically linked library, with all debugging symbols
    present and no optimization present. This is intended to allow debugging through an executable
    which links against this library.
    * This defines the macro `DEBUG`.

* release
    * This will build the library into a statically linked library, with no debugging symbols,
    optimization enabled, and the resulting library will be stripped. This is the primary target
    for use in other applications.
    * This un-defines the macro `DEBUG`.

* clean
    * This will remove all of the object files from the build tree, leaving the finished targets
    intact.

* clean-hard
    * This will remove all object files and target files from the build tree.

* all
    * This will build the `test` target first, regardless of whether or not Make was specified with the -j option.
    * If and only if the `test` target builds successfully will the `debugger`, `debug`, and `release` targets be built.
    These targets do respect the -j option.

* remake
    * Execute a full `clean`, followed by an `all`.

There is no target to install the library, mostly due to the fact that this should not be
used outside of educational or exploratory purposes. If you do wish to install the
library, simply add the `release` target to your `$LD_LIBRARY_PATH` and the top-level header
`libcrypto.h` to your `$INCLUDE_PATH`.

If you want to build the library into some larger project, the top-level Makefile
can be called easily from another Makefile. Simply ensure the correct target(s)
are passed down using a rule similar to `$(MAKE) -C <libcrypto directory> $(MAKECMDGOALS)`.
# Possible Extensions

This library is far from *complete*, from the learning perspective. Additional ciphers,
additional modes of operation, message authentication codes, would all be valuable
additions to explore. In addition, the interface presented by the library is somewhat
limiting, in only providing buffer-buffer **OR** stream-stream operations. Extension
to simplify buffer-stream and vice versa would certainly lead to a more amenable
interface for exploring related cryptographic areas as TLS, Disk Encryption, or VPN
operation.

Another major area of improvement or learning is to better encapsulate and understand
the process of Initialization Vector selection/generation, Key Generation/Exchange, and protocol
negotiation. The current design essentially implies a separate secure channel for sharing
this information; not ideal for learning about these topics.

Ideally, the `Cipher_t` as a black-box cipher object continues to serve as the
primary object of this library, regardless of the underlying algorithm, mode, source,
or destination of data.

# Examples

A simple example to provide an introduction to the library is shown below.
This will compile a very basic command-line utility to read from STDIN until
EOF, printing the encrypted result to STDOUT.

```C
#include <unistd.h>

#include "libcrypto.h"

/*
    Define an arbitrary Key and Nonce / Initialization Vector.

    The lengths of these must match the length
    expected for the requested Cipher Algorithm.

    This example uses AES_256, so these will be
    256-bit and 128-bit respectively.
*/
const uint32_t Key[8] = { 0x00 };
const uint32_t Nonce[4] = { 0x00 };

int main(int argc, char** argv) {

    Cipher_t* Cipher = Cipher_Prepare(AES_256, Cipher_Mode_CTR, Key, Nonce);
    if ( NULL == Cipher ) {
        return -1;
    }

    Cipher_Encrypt_Stream(Cipher, STDIN_FILENO, STDOUT_FILENO);

    Cipher_Release(Cipher);
    return 0;
}
```

Another example, showing how to encrypt an existing buffer is shown below.

```C
#include <stddef.h>

#include "libcrypto.h"

/*
    Define an arbitrary Key and Nonce / Initialization Vector.

    The lengths of these must match the length
    expected for the requested Cipher Algorithm.

    This example uses AES_256, so these will be
    256-bit and 128-bit respectively.
*/
const uint32_t Key[8] = { 0x00 };
const uint32_t Nonce[4] = { 0x00 };

int main(int argc, char** argv) {

    unsigned char* Buffer = NULL;
    size_t BufferLength = 0;
    Cipher_t* Cipher = NULL;

    /*
        Return a buffer from some external function.
        BufferLength holds the length in bytes.
    */
    Buffer = Get_Buffer(&BufferLength);
    Cipher = Cipher_Prepare(AES_256, Cipher_Mode_CTR, Key, Nonce);
    if ( NULL == Cipher ) {
        return -1;
    }

    /*
        The Cipher_Encrypt function (and Cipher_Decrypt) are both
        safe to use the same buffer as input and output.
        The contents will be safely updated to the
        corresponding result.
    */
    Cipher_Encrypt(Cipher, Buffer, BufferLength, Buffer);

    free(Buffer);
    Cipher_Release(Cipher);
    return 0;
}
```

These examples can be easily compiled and tested by copying the source code here to a 
file "main.c" in a directory with the libcrpyto.a release library, and the libcrypto.h header file.

Compile the executables with:
```shell
gcc -o libcrypto-example.out main.c libcrypto.a
```