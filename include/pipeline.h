#ifndef OMP_PIPELINE_H
#define OMP_PIPELINE_H

#include "common.h"
#include "connection.h"
#include "identify.h"

typedef struct {
    uint16_t server_port;
    bool hide_sync;
    bool show_hex;
    uint32_t rpc_filter[256];
    size_t rpc_filter_count;
    char client_filter[64];
    uint64_t packet_count;
    uint64_t rate_last_count;
    double rate_last_time;
    bool show_rate;
    FILE *log_file;
    ConnectionTable connections;
} ViewerState;

void viewer_init(ViewerState *vs, uint16_t server_port);
void viewer_free(ViewerState *vs);
void viewer_set_color(bool enabled);
void viewer_set_log_file(ViewerState *vs, FILE *f);
void viewer_process_udp(ViewerState *vs, UdpPacket *pkt, uint8_t *work_buf, size_t work_size);

#endif
