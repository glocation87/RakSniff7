#ifndef OMP_PCAP_READER_H
#define OMP_PCAP_READER_H

#include "common.h"
#include <pcap.h>

typedef struct {
    pcap_t *handle;
    bool is_live;
    uint16_t server_port;
    int datalink_type;
} PcapReader;

bool pcap_reader_open_file(PcapReader *reader, const char *path, uint16_t server_port);
bool pcap_reader_open_live(PcapReader *reader, const char *iface, uint16_t server_port);
bool pcap_reader_next(PcapReader *reader, UdpPacket *pkt, uint8_t *buf, size_t buf_size);
void pcap_reader_close(PcapReader *reader);

#endif
