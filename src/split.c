#include "split.h"

void split_tracker_init(SplitTracker *st) {
    st->head = NULL;
}

static void free_entry(SplitEntry *e) {
    if (e->parts) {
        for (uint16_t i = 0; i < e->split_count; i++) {
            free(e->parts[i]);
        }
        free(e->parts);
    }
    free(e->part_lens);
    free(e);
}

void split_tracker_free(SplitTracker *st) {
    SplitEntry *cur = st->head;
    while (cur) {
        SplitEntry *next = cur->next;
        free_entry(cur);
        cur = next;
    }
    st->head = NULL;
}

static SplitEntry *find_entry(SplitTracker *st, uint64_t conn_key, uint16_t split_id) {
    SplitEntry *cur = st->head;
    while (cur) {
        if (cur->conn_key == conn_key && cur->split_id == split_id) return cur;
        cur = cur->next;
    }
    return NULL;
}

static SplitEntry *create_entry(SplitTracker *st, uint64_t conn_key, uint16_t split_id, uint16_t split_count) {
    SplitEntry *e = calloc(1, sizeof(SplitEntry));
    if (!e) return NULL;

    e->split_id = split_id;
    e->split_count = split_count;
    e->received = 0;
    e->conn_key = conn_key;
    e->parts = calloc(split_count, sizeof(uint8_t *));
    e->part_lens = calloc(split_count, sizeof(size_t));
    if (!e->parts || !e->part_lens) {
        free_entry(e);
        return NULL;
    }
    e->next = st->head;
    st->head = e;
    return e;
}

static void remove_entry(SplitTracker *st, SplitEntry *target) {
    SplitEntry **pp = &st->head;
    while (*pp) {
        if (*pp == target) {
            *pp = target->next;
            free_entry(target);
            return;
        }
        pp = &(*pp)->next;
    }
}

uint8_t *split_tracker_add(SplitTracker *st, uint64_t conn_key,
                           const InternalPacket *pkt, size_t *assembled_len) {
    SplitEntry *e = find_entry(st, conn_key, pkt->split_id);
    if (!e) {
        e = create_entry(st, conn_key, pkt->split_id, pkt->split_count);
        if (!e) return NULL;
    }

    if (pkt->split_index >= e->split_count) return NULL;

    if (!e->parts[pkt->split_index]) {
        e->parts[pkt->split_index] = malloc(pkt->data_len);
        if (!e->parts[pkt->split_index]) return NULL;
        memcpy(e->parts[pkt->split_index], pkt->data, pkt->data_len);
        e->part_lens[pkt->split_index] = pkt->data_len;
        e->received++;
    }

    if (e->received < e->split_count) return NULL;

    // All parts received — assemble
    size_t total = 0;
    for (uint16_t i = 0; i < e->split_count; i++) {
        total += e->part_lens[i];
    }

    uint8_t *assembled = malloc(total);
    if (!assembled) return NULL;

    size_t offset = 0;
    for (uint16_t i = 0; i < e->split_count; i++) {
        memcpy(assembled + offset, e->parts[i], e->part_lens[i]);
        offset += e->part_lens[i];
    }
    *assembled_len = total;

    remove_entry(st, e);
    return assembled;
}
