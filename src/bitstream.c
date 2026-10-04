#include "bitstream.h"

void bs_init(BitStream *bs, const uint8_t *data, size_t byte_len) {
    bs->data = data;
    bs->byte_len = byte_len;
    bs->bit_pos = 0;
    bs->bit_len = byte_len * 8;
}

void bs_init_bits(BitStream *bs, const uint8_t *data, size_t bit_len) {
    bs->data = data;
    bs->byte_len = (bit_len + 7) / 8;
    bs->bit_pos = 0;
    bs->bit_len = bit_len;
}

size_t bs_bits_remaining(const BitStream *bs) {
    if (bs->bit_pos >= bs->bit_len) return 0;
    return bs->bit_len - bs->bit_pos;
}

bool bs_read_bit(BitStream *bs) {
    if (bs->bit_pos >= bs->bit_len) return false;
    size_t byte_idx = bs->bit_pos >> 3;
    size_t bit_idx = 7 - (bs->bit_pos & 7);  // MSB first
    bs->bit_pos++;
    return (bs->data[byte_idx] >> bit_idx) & 1;
}

bool bs_read_bits(BitStream *bs, uint8_t *out, size_t num_bits) {
    if (bs_bits_remaining(bs) < num_bits) return false;

    size_t num_bytes = (num_bits + 7) / 8;
    memset(out, 0, num_bytes);

    for (size_t i = 0; i < num_bits; i++) {
        size_t byte_idx = bs->bit_pos >> 3;
        size_t bit_idx = 7 - (bs->bit_pos & 7);
        bool bit = (bs->data[byte_idx] >> bit_idx) & 1;

        size_t out_byte = i >> 3;
        size_t out_bit = 7 - (i & 7);
        if (bit) out[out_byte] |= (1 << out_bit);

        bs->bit_pos++;
    }
    return true;
}

bool bs_read_u8(BitStream *bs, uint8_t *out) {
    return bs_read_bits(bs, out, 8);
}

bool bs_read_u16(BitStream *bs, uint16_t *out) {
    uint8_t buf[2];
    if (!bs_read_bits(bs, buf, 16)) return false;
    *out = ((uint16_t)buf[0] << 8) | buf[1];
    return true;
}

bool bs_read_u32(BitStream *bs, uint32_t *out) {
    uint8_t buf[4];
    if (!bs_read_bits(bs, buf, 32)) return false;
    *out = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8) | buf[3];
    return true;
}

bool bs_read_bytes(BitStream *bs, uint8_t *out, size_t num_bytes) {
    return bs_read_bits(bs, out, num_bytes * 8);
}

// RakNet 2.52 ReadCompressed: processes bytes from MSB to LSB.
// For each byte except the last:
//   Read 1 bit. If 1, byte is zero — continue. If 0, read remaining bytes raw.
// For the last byte:
//   Read 1 bit. If 1, read 4 bits (lower nibble). If 0, read 8 bits.
bool bs_read_compressed(BitStream *bs, uint8_t *out, size_t num_bytes, bool unsigned_data) {
    (void)unsigned_data;
    size_t current_byte = num_bytes - 1;

    memset(out, 0, num_bytes);

    while (current_byte > 0) {
        if (bs_bits_remaining(bs) < 1) return false;
        bool is_zero = bs_read_bit(bs);

        if (is_zero) {
            out[current_byte] = 0;
            current_byte--;
        } else {
            for (size_t i = 0; i <= current_byte; i++) {
                if (!bs_read_u8(bs, &out[i])) return false;
            }
            return true;
        }
    }

    if (bs_bits_remaining(bs) < 1) return false;
    bool half = bs_read_bit(bs);

    if (half) {
        uint8_t nibble = 0;
        if (bs_bits_remaining(bs) < 4) return false;
        if (!bs_read_bits(bs, &nibble, 4)) return false;
        out[0] = nibble >> 4;
    } else {
        if (!bs_read_u8(bs, &out[0])) return false;
    }
    return true;
}

bool bs_read_compressed_u16(BitStream *bs, uint16_t *out) {
    uint8_t buf[2];
    if (!bs_read_compressed(bs, buf, 2, true)) return false;
    *out = ((uint16_t)buf[1] << 8) | buf[0];
    return true;
}

bool bs_read_compressed_u32(BitStream *bs, uint32_t *out) {
    uint8_t buf[4];
    if (!bs_read_compressed(bs, buf, 4, true)) return false;
    *out = ((uint32_t)buf[3] << 24) | ((uint32_t)buf[2] << 16) |
           ((uint32_t)buf[1] << 8) | buf[0];
    return true;
}

void bs_align(BitStream *bs) {
    size_t mod = bs->bit_pos & 7;
    if (mod != 0) {
        bs->bit_pos += 8 - mod;
    }
}

void bs_skip_bits(BitStream *bs, size_t num_bits) {
    bs->bit_pos += num_bits;
    if (bs->bit_pos > bs->bit_len) {
        bs->bit_pos = bs->bit_len;
    }
}
