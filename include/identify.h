#ifndef OMP_IDENTIFY_H
#define OMP_IDENTIFY_H

#include "common.h"

typedef enum {
    MSG_RPC,
    MSG_PACKET,
    MSG_INTERNAL,
    MSG_UNKNOWN
} MessageType;

typedef struct {
    MessageType type;
    uint8_t packet_id;
    uint32_t rpc_id;
    const char *name;
    const uint8_t *payload;
    size_t payload_len;
    uint32_t payload_bit_len;
} IdentifiedMessage;

// RakNet internal message IDs
#define ID_INTERNAL_PING            0x00
#define ID_PING_OPEN_CONNECTIONS    0x01
#define ID_CONNECTED_PONG           0x03
#define ID_CONNECTION_REQUEST       0x07
#define ID_AUTH_KEY                 0x15
#define ID_RPC                      0x19
#define ID_TIMESTAMP                0x28
#define ID_USER_PACKET_ENUM         0x4B

// Sync packet IDs (after reliability layer)
#define ID_PLAYER_SYNC              0xCB  // 203
#define ID_VEHICLE_SYNC             0xCC  // 204
#define ID_PASSENGER_SYNC           0xCD  // 205
#define ID_AIM_SYNC                 0xCE  // 206
#define ID_UNOCCUPIED_SYNC          0xCF  // 207
#define ID_TRAILER_SYNC             0xD0  // 208
#define ID_BULLET_SYNC              0xD1  // 209
#define ID_SPECTATING_SYNC          0xD2  // 210

bool identify_message(const uint8_t *data, size_t len, PacketDirection dir,
                      IdentifiedMessage *out);

const char *rpc_name(uint32_t rpc_id, PacketDirection dir);
const char *packet_id_name(uint8_t id);

#endif
