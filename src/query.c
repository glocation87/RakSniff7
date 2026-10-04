#include "query.h"

bool query_is_query_packet(const uint8_t *data, size_t len) {
    if (len < 11) return false;
    return data[0] == 'S' && data[1] == 'A' && data[2] == 'M' && data[3] == 'P';
}

QueryResult query_decode(const uint8_t *data, size_t len) {
    QueryResult result = { QUERY_UNKNOWN, "Unknown" };

    if (!query_is_query_packet(data, len)) return result;

    // Bytes 4-7: server IP, bytes 8-9: server port, byte 10: opcode
    uint8_t opcode = data[10];
    result.opcode = (QueryOpcode)opcode;

    switch (opcode) {
        case 'i': result.name = "ServerInfo";    break;
        case 'r': result.name = "ServerRules";   break;
        case 'c': result.name = "ClientList";    break;
        case 'p': result.name = "Ping";          break;
        case 'o': result.name = "RCON";          break;
        case 'x': result.name = "Extra";         break;
        default:  result.name = "UnknownQuery";  break;
    }
    return result;
}
