#include "omp_encrypt.h"

#define ID_USER_PACKET_ENUM 0x4B
#define OMP_MAGIC 0x006F6D70

bool omp_is_access_reply(const uint8_t *data, size_t len) {
    if (len != 13) return false;
    if (data[0] != ID_USER_PACKET_ENUM) return false;

    uint32_t magic = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                     ((uint32_t)data[3] << 8) | data[4];
    return magic == OMP_MAGIC;
}

bool omp_extract_key(const uint8_t *data, size_t len, uint8_t key_out[4]) {
    if (len < 9) return false;
    // Bytes 5-8 are the 4-byte XOR key
    memcpy(key_out, data + 5, 4);
    return true;
}

bool omp_decrypt(uint8_t *data, size_t len, const uint8_t key[4]) {
    if (len < 2) return false;

    // Skip checksum byte at index 0
    for (size_t i = 1; i < len; i++) {
        data[i] ^= key[(i - 1) % 4];
    }
    return true;
}
