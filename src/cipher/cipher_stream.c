#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "../../include/libcrypto.h"
#include "include/cipher.h"

/*
    Local private function prototypes.

    These just wrap the basic read() and write() calls,
    to give them a more friendly interface for these cipher functions.
*/

int Read_Stream(Cipher_t *Cipher, int fd, void *buf, size_t nBytes, ssize_t *nRead);
int Write_Stream(int fd, const void *buf, size_t nBytes, ssize_t *nWritten);

ssize_t Cipher_Encrypt_Stream(Cipher_t *Cipher, int fd_In, int fd_Out) {

    uint8_t *Buffer = NULL;
    ssize_t nRead = 0;
    ssize_t nWritten = 0;

    if ((NULL == Cipher) || (fd_In < 0) || (fd_Out < 0)) {
        return -1;
    }

    Buffer = (uint8_t *)malloc(sizeof(uint8_t) * CIPHER_STREAM_BUFFER_SIZE);
    if (NULL == Buffer) {
        return -1;
    }

    while (1) {

        if (0 != Read_Stream(Cipher, fd_In, Buffer, CIPHER_STREAM_BUFFER_SIZE, &nRead)) {
            free(Buffer);
            return -1;
        }

        if (0 == nRead) {
            free(Buffer);
            return nWritten;
        }

        if (0 != Cipher_Encrypt(Cipher, (const void *)Buffer, (size_t)nRead, Buffer)) {
            free(Buffer);
            return -1;
        }

        if (0 != Write_Stream(fd_Out, (const void *)Buffer, (size_t)nRead, &nWritten)) {
            free(Buffer);
            return -1;
        }
    }
}

ssize_t Cipher_Decrypt_Stream(Cipher_t *Cipher, int fd_In, int fd_Out) {

    uint8_t *Buffer = NULL;
    ssize_t nRead = 0;
    ssize_t nWritten = 0;

    if ((NULL == Cipher) || (fd_In < 0) || (fd_Out < 0)) {
        return -1;
    }

    Buffer = (uint8_t *)malloc(sizeof(uint8_t) * CIPHER_STREAM_BUFFER_SIZE);
    if (NULL == Buffer) {
        return -1;
    }

    while (1) {

        if (0 != Read_Stream(Cipher, fd_In, Buffer, CIPHER_STREAM_BUFFER_SIZE, &nRead)) {
            free(Buffer);
            return -1;
        }

        if (0 == nRead) {
            free(Buffer);
            return nWritten;
        }

        if (0 != Cipher_Decrypt(Cipher, (const void *)Buffer, (size_t)nRead, Buffer)) {
            free(Buffer);
            return -1;
        }

        if (0 != Write_Stream(fd_Out, (const void *)Buffer, (size_t)nRead, &nWritten)) {
            free(Buffer);
            return -1;
        }
    }
}

int Read_Stream(Cipher_t *Cipher, int fd, void *buf, size_t nBytes, ssize_t *nRead) {

    ssize_t MinBlockRead;
    ssize_t BytesRead;
    ssize_t UnreadSize;
    off_t CurrentPos, EOFPos;
    *nRead = 0;

    if (0 == nBytes) {
        return 0;
    }

    CurrentPos = lseek(fd, 0, SEEK_CUR);
    EOFPos = lseek(fd, 0, SEEK_END);
    lseek(fd, CurrentPos, SEEK_SET);

    MinBlockRead = (ssize_t)Cipher->BlockLength(Cipher->Context);

    while (1) {

        BytesRead = read(fd, &(((uint8_t *)buf)[*nRead]), nBytes);

        /*
            Handle errors
        */
        if (0 > BytesRead) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                continue;
            default:
                return 1;
            }
        }

        /*
            Handle EOF from read
        */
        if (0 == BytesRead) {
            return 0;
        }

        /*
            Handle file being EOF
        */
        CurrentPos = lseek(fd, 0, SEEK_CUR);
        EOFPos = lseek(fd, 0, SEEK_END);
        lseek(fd, CurrentPos, SEEK_SET);

        if (CurrentPos == EOFPos) {
            *nRead += BytesRead;
            return 0;
        }

        *nRead += BytesRead;
        UnreadSize = (*nRead % MinBlockRead);

        /*
            If the read is already block aligned, return
            and use it.
        */
        if (0 == UnreadSize) {
            return 0;
        }

        /*
            Rewind the file, and decrement the size of the read
            to block alignment.
        */
        lseek(fd, -(int)UnreadSize, SEEK_CUR);
        *nRead -= UnreadSize;
        return 0;
    }
}

int Write_Stream(int fd, const void *buf, size_t nBytes, ssize_t *nWritten) {

    ssize_t written = 0;

    if (0 == nBytes) {
        return 0;
    }

    while (1) {

        written = write(fd, &(((const uint8_t *)buf)[written]), nBytes - (size_t)written);

        if (written < 0) {
            switch (errno) {
            case EAGAIN:
            case EINTR:
                continue;
            default:
                return 1;
            }
        } else if (written == (ssize_t)nBytes) {
            *nWritten += written;
            return 0;
        }
    }
}
