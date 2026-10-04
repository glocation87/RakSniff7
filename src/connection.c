#include "connection.h"

uint64_t conn_key(uint32_t ip, uint16_t port) {
    return ((uint64_t)ip << 16) | port;
}

void conn_table_init(ConnectionTable *ct) {
    ct->head = NULL;
    split_tracker_init(&ct->splits);
}

void conn_table_free(ConnectionTable *ct) {
    Connection *cur = ct->head;
    while (cur) {
        Connection *next = cur->next;
        free(cur);
        cur = next;
    }
    ct->head = NULL;
    split_tracker_free(&ct->splits);
}

Connection *conn_table_get(ConnectionTable *ct, uint32_t client_ip, uint16_t client_port) {
    Connection *cur = ct->head;
    while (cur) {
        if (cur->client_ip == client_ip && cur->client_port == client_port) return cur;
        cur = cur->next;
    }
    return NULL;
}

Connection *conn_table_get_or_create(ConnectionTable *ct, uint32_t client_ip, uint16_t client_port) {
    Connection *c = conn_table_get(ct, client_ip, client_port);
    if (c) return c;

    c = calloc(1, sizeof(Connection));
    if (!c) return NULL;

    c->client_ip = client_ip;
    c->client_port = client_port;
    c->connected = false;
    c->has_omp_key = false;
    dedup_init(&c->dedup_c2s);
    dedup_init(&c->dedup_s2c);
    c->next = ct->head;
    ct->head = c;
    return c;
}
