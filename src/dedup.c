#include "dedup.h"

void dedup_init(DedupTracker *dt) {
    memset(dt->seen, 0xFF, sizeof(dt->seen));
    dt->count = 0;
    dt->head = 0;
}

bool dedup_is_duplicate(DedupTracker *dt, uint32_t message_number) {
    for (size_t i = 0; i < dt->count; i++) {
        if (dt->seen[i] == message_number) return true;
    }
    dt->seen[dt->head] = message_number;
    dt->head = (dt->head + 1) % DEDUP_WINDOW;
    if (dt->count < DEDUP_WINDOW) dt->count++;
    return false;
}
