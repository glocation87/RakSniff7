#ifndef OMP_RAKNET_H
#define OMP_RAKNET_H

#include "common.h"
#include "bitstream.h"

typedef enum {
    UNRELIABLE            = 0,
    UNRELIABLE_SEQUENCED  = 1,
    RELIABLE              = 2,
    RELIABLE_ORDERED      = 3,
    RELIABLE_SEQUENCED    = 4
} Reliability;

typedef struct {
    uint32_t message_number;
    Reliability reliability;
    uint8_t ordering_channel;
    uint32_t ordering_index;
    uint16_t split_count;
    uint16_t split_id;
    uint32_t split_index;
    bool is_split;
    uint8_t *data;
    size_t data_len;
} InternalPacket;

#define MAX_INTERNAL_PACKETS 64

typedef struct {
    uint32_t acks[256];
    size_t ack_count;
    InternalPacket packets[MAX_INTERNAL_PACKETS];
    size_t packet_count;
    bool has_acks;
} RakNetDatagram;

bool raknet_parse_datagram(const uint8_t *data, size_t len, RakNetDatagram *out,
                           uint8_t *scratch, size_t scratch_size);
const char *reliability_name(Reliability r);

#endif
