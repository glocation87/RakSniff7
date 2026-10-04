#ifndef OMP_HANDSHAKE_H
#define OMP_HANDSHAKE_H

#include "common.h"

typedef enum {
    HS_OPEN_CONNECTION_REQUEST   = 0x01,
    HS_OPEN_CONNECTION_REPLY     = 0x02,
    HS_OPEN_CONNECTION_COOKIE    = 0x03,
    HS_CONNECTION_REQUEST        = 0x07,
    HS_CONNECTION_REQUEST_ACCEPTED = 0x08,
    HS_NEW_INCOMING_CONNECTION   = 0x0E,
    HS_DISCONNECTION             = 0x13,
    HS_CONNECTION_LOST           = 0x14,
    HS_AUTH_KEY                  = 0x15,
    HS_NONE                      = 0xFF
} HandshakeType;

typedef struct {
    HandshakeType type;
    const char *name;
} HandshakeResult;

HandshakeResult handshake_check(const uint8_t *data, size_t len, bool is_connected);
const char *handshake_type_name(HandshakeType type);

#endif
