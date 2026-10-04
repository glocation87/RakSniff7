#ifndef OMP_CONNECTION_H
#define OMP_CONNECTION_H

#include "common.h"
#include "dedup.h"
#include "split.h"

typedef struct Connection {
    uint32_t client_ip;
    uint16_t client_port;
    bool connected;
    bool has_omp_key;
    uint8_t omp_key[4];
    double connect_time;
    uint64_t packets_c2s;
    uint64_t packets_s2c;
    DedupTracker dedup_c2s;
    DedupTracker dedup_s2c;
    struct Connection *next;
} Connection;

typedef struct {
    Connection *head;
    SplitTracker splits;
} ConnectionTable;

void conn_table_init(ConnectionTable *ct);
void conn_table_free(ConnectionTable *ct);
Connection *conn_table_get(ConnectionTable *ct, uint32_t client_ip, uint16_t client_port);
Connection *conn_table_get_or_create(ConnectionTable *ct, uint32_t client_ip, uint16_t client_port);
uint64_t conn_key(uint32_t ip, uint16_t port);

#endif
