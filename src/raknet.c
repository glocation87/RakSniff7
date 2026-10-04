#include "raknet.h"

const char *reliability_name(Reliability r) {
    switch (r) {
        case UNRELIABLE:           return "Unreliable";
        case UNRELIABLE_SEQUENCED: return "UnreliableSeq";
        case RELIABLE:             return "Reliable";
        case RELIABLE_ORDERED:     return "ReliableOrd";
        case RELIABLE_SEQUENCED:   return "ReliableSeq";
        default:                   return "Unknown";
    }
}

// Parse the ack section at the start of a RakNet datagram.
// Format: hasAcks (1 bit), if true: ack count (compressed u16),
// then for each ack: isRange (1 bit), if range: min+max message numbers,
// else single message number. Message numbers are compressed u32.
static bool parse_acks(BitStream *bs, RakNetDatagram *out) {
    out->has_acks = bs_read_bit(bs);
    if (!out->has_acks) {
        out->ack_count = 0;
        return true;
    }

    uint16_t count;
    if (!bs_read_compressed_u16(bs, &count)) return false;

    out->ack_count = 0;
    for (uint16_t i = 0; i < count; i++) {
        // Each ack entry starts with a "has range max" bit (actually inverted:
        // 0 = range, 1 = single in the original code, but let's read as RakNet does it)
        // In RakNet 2.52: read 1 bit. If 0 (maxEqualToMin=false), read min and max.
        // If 1 (maxEqualToMin=true), read just one value.
        bool max_equals_min = bs_read_bit(bs);

        uint32_t msg_min;
        if (!bs_read_compressed_u32(bs, &msg_min)) return false;

        if (max_equals_min) {
            if (out->ack_count < 256) {
                out->acks[out->ack_count++] = msg_min;
            }
        } else {
            uint32_t msg_max;
            if (!bs_read_compressed_u32(bs, &msg_max)) return false;
            for (uint32_t m = msg_min; m <= msg_max && out->ack_count < 256; m++) {
                out->acks[out->ack_count++] = m;
            }
        }
    }
    return true;
}

// Parse one internal packet from the bitstream.
// RakNet 2.52 RAKNET_LEGACY format:
//   - message number: compressed u32
//   - reliability: 4 bits
//   - if sequenced/ordered: ordering channel (5 bits) + ordering index (compressed u32)
//   - if split: split_count (compressed u16), split_id (compressed u16), split_index (compressed u32)
//   - data length in bits: compressed u16
//   - align to byte boundary
//   - data bytes
static bool parse_internal_packet(BitStream *bs, InternalPacket *pkt, uint8_t *scratch, size_t *scratch_offset, size_t scratch_size) {
    if (!bs_read_compressed_u32(bs, &pkt->message_number)) return false;

    uint8_t rel_bits = 0;
    if (!bs_read_bits(bs, &rel_bits, 4)) return false;
    pkt->reliability = (Reliability)(rel_bits >> 4);

    pkt->ordering_channel = 0;
    pkt->ordering_index = 0;
    if (pkt->reliability == UNRELIABLE_SEQUENCED ||
        pkt->reliability == RELIABLE_ORDERED ||
        pkt->reliability == RELIABLE_SEQUENCED) {
        uint8_t ch = 0;
        if (!bs_read_bits(bs, &ch, 5)) return false;
        pkt->ordering_channel = ch >> 3;
        if (!bs_read_compressed_u32(bs, &pkt->ordering_index)) return false;
    }

    pkt->is_split = bs_read_bit(bs);
    pkt->split_count = 0;
    pkt->split_id = 0;
    pkt->split_index = 0;
    if (pkt->is_split) {
        if (!bs_read_compressed_u16(bs, &pkt->split_count)) return false;
        if (!bs_read_compressed_u16(bs, &pkt->split_id)) return false;
        if (!bs_read_compressed_u32(bs, &pkt->split_index)) return false;
    }

    uint16_t data_bit_len;
    if (!bs_read_compressed_u16(bs, &data_bit_len)) return false;

    bs_align(bs);

    size_t data_byte_len = (data_bit_len + 7) / 8;
    if (*scratch_offset + data_byte_len > scratch_size) return false;

    pkt->data = scratch + *scratch_offset;
    pkt->data_len = data_byte_len;

    if (!bs_read_bytes(bs, scratch + *scratch_offset, data_byte_len)) return false;
    *scratch_offset += data_byte_len;

    return true;
}

bool raknet_parse_datagram(const uint8_t *data, size_t len, RakNetDatagram *out,
                           uint8_t *scratch, size_t scratch_size) {
    BitStream bs;
    bs_init(&bs, data, len);

    out->ack_count = 0;
    out->packet_count = 0;

    if (!parse_acks(&bs, out)) return false;

    // Parse message flag
    bool has_messages = bs_read_bit(bs);
    if (!has_messages) return true;

    size_t scratch_offset = 0;

    while (bs_bits_remaining(&bs) >= 32 && out->packet_count < MAX_INTERNAL_PACKETS) {
        if (!parse_internal_packet(&bs, &out->packets[out->packet_count],
                                   scratch, &scratch_offset, scratch_size)) {
            break;
        }
        out->packet_count++;
    }

    return out->packet_count > 0 || out->has_acks;
}
