#ifndef OMP_DEDUP_H
#define OMP_DEDUP_H

#include "common.h"

#define DEDUP_WINDOW 4096

typedef struct {
    uint32_t seen[DEDUP_WINDOW];
    size_t count;
    size_t head;
} DedupTracker;

void dedup_init(DedupTracker *dt);
bool dedup_is_duplicate(DedupTracker *dt, uint32_t message_number);

#endif
