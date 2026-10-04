#ifndef OMP_OMP_ENCRYPT_H
#define OMP_OMP_ENCRYPT_H

#include "common.h"

bool omp_is_access_reply(const uint8_t *data, size_t len);
bool omp_extract_key(const uint8_t *data, size_t len, uint8_t key_out[4]);
bool omp_decrypt(uint8_t *data, size_t len, const uint8_t key[4]);

#endif
