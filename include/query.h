#ifndef OMP_QUERY_H
#define OMP_QUERY_H

#include "common.h"

typedef enum {
    QUERY_INFO       = 'i',
    QUERY_RULES      = 'r',
    QUERY_CLIENTS    = 'c',
    QUERY_PING       = 'p',
    QUERY_RCON       = 'o',
    QUERY_EXTRA      = 'x',
    QUERY_UNKNOWN    = 0
} QueryOpcode;

typedef struct {
    QueryOpcode opcode;
    const char *name;
} QueryResult;

bool query_is_query_packet(const uint8_t *data, size_t len);
QueryResult query_decode(const uint8_t *data, size_t len);

#endif
