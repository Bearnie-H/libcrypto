#include "include/AES.h"

void AES_Counter_Increment(void *Counter) {
    (*((uint64_t *)Counter))++;
    return;
}
