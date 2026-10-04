#ifndef OMP_SPLIT_H
#define OMP_SPLIT_H

#include "common.h"
#include "raknet.h"

typedef struct SplitEntry {
    uint16_t split_id;
    uint16_t split_count;
    uint16_t received;
    uint8_t **parts;
    size_t *part_lens;
    uint64_t conn_key;
    struct SplitEntry *next;
} SplitEntry;

typedef struct {
    SplitEntry *head;
} SplitTracker;

void split_tracker_init(SplitTracker *st);
void split_tracker_free(SplitTracker *st);

// Returns assembled data if complete (caller must free), NULL if still waiting.
// assembled_len is set on success.
uint8_t *split_tracker_add(SplitTracker *st, uint64_t conn_key,
                           const InternalPacket *pkt, size_t *assembled_len);

#endif
