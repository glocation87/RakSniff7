#include "pcap_reader.h"

#ifdef _WIN32
#include <windows.h>
static void sleep_seconds(double seconds) {
    if (seconds <= 0) return;
    DWORD ms = (DWORD)(seconds * 1000.0);
    Sleep(ms);
}
static double wall_now(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (double)(t - 116444736000000000ULL) / 10000000.0;
}
#else
#include <time.h>
static void sleep_seconds(double seconds) {
    if (seconds <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)seconds;
    ts.tv_nsec = (long)((seconds - ts.tv_sec) * 1e9);
    nanosleep(&ts, NULL);
}
static double wall_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
#endif

bool pcap_reader_open_file(PcapReader *reader, const char *path, uint16_t server_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    reader->handle = pcap_open_offline(path, errbuf);
    if (!reader->handle) {
        fprintf(stderr, "pcap_open_offline: %s\n", errbuf);
        return false;
    }
    reader->is_live = false;
    reader->server_port = server_port;
    reader->datalink_type = pcap_datalink(reader->handle);
    reader->realtime_speed = 0.0;
    reader->first_pcap_ts = 0.0;
    reader->first_wall_ts = 0.0;
    return true;
}

void pcap_reader_set_realtime(PcapReader *reader, double speed) {
    reader->realtime_speed = speed;
}

bool pcap_reader_open_live(PcapReader *reader, const char *iface, uint16_t server_port, const char *bpf) {
    char errbuf[PCAP_ERRBUF_SIZE];
    reader->handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);
    if (!reader->handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return false;
    }
    reader->is_live = true;
    reader->server_port = server_port;
    reader->datalink_type = pcap_datalink(reader->handle);

    char filter_str[512];
    if (bpf && bpf[0]) {
        snprintf(filter_str, sizeof(filter_str), "%s", bpf);
    } else {
        snprintf(filter_str, sizeof(filter_str), "udp port %u", server_port);
    }
    struct bpf_program fp;
    if (pcap_compile(reader->handle, &fp, filter_str, 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(reader->handle, &fp);
        pcap_freecode(&fp);
    } else {
        fprintf(stderr, "warning: failed to compile BPF filter: %s\n", pcap_geterr(reader->handle));
    }
    return true;
}

static size_t link_header_len(int datalink_type) {
    switch (datalink_type) {
        case DLT_EN10MB:    return 14;   // Ethernet
        case DLT_NULL:      return 4;    // BSD loopback
        case DLT_LOOP:      return 4;
        case DLT_LINUX_SLL: return 16;   // Linux cooked
        case DLT_RAW:       return 0;    // Raw IP
        default:            return 14;
    }
}

bool pcap_reader_next(PcapReader *reader, UdpPacket *pkt, uint8_t *buf, size_t buf_size) {
    struct pcap_pkthdr *hdr;
    const uint8_t *raw;

    while (pcap_next_ex(reader->handle, &hdr, &raw) == 1) {
        if (!reader->is_live && reader->realtime_speed > 0.0) {
            double pcap_ts = hdr->ts.tv_sec + hdr->ts.tv_usec / 1000000.0;
            if (reader->first_pcap_ts == 0.0) {
                reader->first_pcap_ts = pcap_ts;
                reader->first_wall_ts = wall_now();
            } else {
                double pcap_delta = (pcap_ts - reader->first_pcap_ts) / reader->realtime_speed;
                double target_wall = reader->first_wall_ts + pcap_delta;
                double now = wall_now();
                sleep_seconds(target_wall - now);
            }
        }

        size_t link_len = link_header_len(reader->datalink_type);
        if (hdr->caplen < link_len + 20) continue;  // too short for IP header

        const uint8_t *ip = raw + link_len;

        // Verify IPv4
        uint8_t ip_ver = (ip[0] >> 4) & 0x0F;
        if (ip_ver != 4) continue;

        uint8_t ip_hdr_len = (ip[0] & 0x0F) * 4;
        uint8_t protocol = ip[9];
        if (protocol != 17) continue;  // Not UDP

        if (hdr->caplen < link_len + ip_hdr_len + 8) continue;

        const uint8_t *udp = ip + ip_hdr_len;
        uint16_t src_port = ((uint16_t)udp[0] << 8) | udp[1];
        uint16_t dst_port = ((uint16_t)udp[2] << 8) | udp[3];
        uint16_t udp_len  = ((uint16_t)udp[4] << 8) | udp[5];

        if (src_port != reader->server_port && dst_port != reader->server_port)
            continue;

        size_t payload_len = udp_len - 8;
        if (payload_len == 0) continue;
        if (payload_len > buf_size) payload_len = buf_size;

        const uint8_t *payload = udp + 8;
        size_t available = hdr->caplen - (payload - raw);
        if (payload_len > available) payload_len = available;

        memcpy(buf, payload, payload_len);

        pkt->src_ip = ((uint32_t)ip[12] << 24) | ((uint32_t)ip[13] << 16) |
                      ((uint32_t)ip[14] << 8) | ip[15];
        pkt->dst_ip = ((uint32_t)ip[16] << 24) | ((uint32_t)ip[17] << 16) |
                      ((uint32_t)ip[18] << 8) | ip[19];
        pkt->src_port = src_port;
        pkt->dst_port = dst_port;
        pkt->server_port = reader->server_port;
        pkt->data = buf;
        pkt->data_len = payload_len;
        pkt->timestamp = hdr->ts.tv_sec + hdr->ts.tv_usec / 1000000.0;

        if (src_port == reader->server_port) {
            pkt->direction = DIR_SERVER_TO_CLIENT;
        } else {
            pkt->direction = DIR_CLIENT_TO_SERVER;
        }
        return true;
    }
    return false;
}

void pcap_reader_close(PcapReader *reader) {
    if (reader->handle) {
        pcap_close(reader->handle);
        reader->handle = NULL;
    }
}
