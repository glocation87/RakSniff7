#include "handshake.h"

const char *handshake_type_name(HandshakeType type) {
    switch (type) {
        case HS_OPEN_CONNECTION_REQUEST:   return "OpenConnectionRequest";
        case HS_OPEN_CONNECTION_REPLY:     return "OpenConnectionReply";
        case HS_OPEN_CONNECTION_COOKIE:    return "OpenConnectionCookie";
        case HS_CONNECTION_REQUEST:        return "ConnectionRequest";
        case HS_CONNECTION_REQUEST_ACCEPTED: return "ConnectionRequestAccepted";
        case HS_NEW_INCOMING_CONNECTION:   return "NewIncomingConnection";
        case HS_DISCONNECTION:            return "DisconnectionNotification";
        case HS_CONNECTION_LOST:          return "ConnectionLost";
        case HS_AUTH_KEY:                 return "AuthKey";
        default:                          return "Unknown";
    }
}

HandshakeResult handshake_check(const uint8_t *data, size_t len, bool is_connected) {
    HandshakeResult result = { HS_NONE, NULL };

    if (len == 0) return result;

    if (!is_connected) {
        uint8_t first = data[0];

        // Open connection request: first byte 0x01, specific length patterns
        if (first == 0x01 && len >= 2) {
            result.type = HS_OPEN_CONNECTION_REQUEST;
            result.name = handshake_type_name(result.type);
            return result;
        }
        if (first == 0x02) {
            result.type = HS_OPEN_CONNECTION_REPLY;
            result.name = handshake_type_name(result.type);
            return result;
        }
        if (first == 0x03) {
            result.type = HS_OPEN_CONNECTION_COOKIE;
            result.name = handshake_type_name(result.type);
            return result;
        }
        if (first == 0x07) {
            result.type = HS_CONNECTION_REQUEST;
            result.name = handshake_type_name(result.type);
            return result;
        }
        if (first == 0x08) {
            result.type = HS_CONNECTION_REQUEST_ACCEPTED;
            result.name = handshake_type_name(result.type);
            return result;
        }
        if (first == 0x15) {
            result.type = HS_AUTH_KEY;
            result.name = handshake_type_name(result.type);
            return result;
        }
    }

    // These can appear any time
    if (data[0] == 0x13) {
        result.type = HS_DISCONNECTION;
        result.name = handshake_type_name(result.type);
        return result;
    }
    if (data[0] == 0x14) {
        result.type = HS_CONNECTION_LOST;
        result.name = handshake_type_name(result.type);
        return result;
    }

    return result;
}
