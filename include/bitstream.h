#ifndef OMP_BITSTREAM_H
#define OMP_BITSTREAM_H

#include "common.h"

typedef struct {
    const uint8_t *data;
    size_t byte_len;
    size_t bit_pos;
    size_t bit_len;
} BitStream;

void bs_init(BitStream *bs, const uint8_t *data, size_t byte_len);
void bs_init_bits(BitStream *bs, const uint8_t *data, size_t bit_len);

size_t bs_bits_remaining(const BitStream *bs);
bool bs_read_bit(BitStream *bs);
bool bs_read_bits(BitStream *bs, uint8_t *out, size_t num_bits);
bool bs_read_u8(BitStream *bs, uint8_t *out);
bool bs_read_u16(BitStream *bs, uint16_t *out);
bool bs_read_u32(BitStream *bs, uint32_t *out);
bool bs_read_bytes(BitStream *bs, uint8_t *out, size_t num_bytes);
bool bs_read_compressed(BitStream *bs, uint8_t *out, size_t num_bytes, bool unsigned_data);
bool bs_read_compressed_u16(BitStream *bs, uint16_t *out);
bool bs_read_compressed_u32(BitStream *bs, uint32_t *out);
void bs_align(BitStream *bs);
void bs_skip_bits(BitStream *bs, size_t num_bits);

#endif
