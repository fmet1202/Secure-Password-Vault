#include "securevault.h"

bool csrf_validate(const char* expected, const char* provided) {
    if (!expected || !provided) return false;
    if (strlen(expected) != 64 || strlen(provided) != 64) return false;
    
    volatile uint8_t diff = 0;
    for (int i = 0; i < 64; i++) {
        diff |= expected[i] ^ provided[i];
    }
    return diff == 0;
}
