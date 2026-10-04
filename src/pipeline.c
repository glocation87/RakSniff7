#include "pipeline.h"
#include "query.h"
#include "decrypt.h"
#include "omp_encrypt.h"
#include "handshake.h"
#include "raknet.h"
#include "split.h"
#include "identify.h"
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
static void enable_ansi(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
}
#else
static void enable_ansi(void) {}
#endif

#define CLR_RESET   "\033[0m"
#define CLR_TIME    "\033[90m"
#define CLR_IP      "\033[36m"
#define CLR_C2S     "\033[33m"
#define CLR_S2C     "\033[35m"
#define CLR_RPC     "\033[1;32m"
#define CLR_SYNC    "\033[34m"
#define CLR_QUERY   "\033[96m"
#define CLR_HS      "\033[1;33m"
#define CLR_OMP     "\033[1;35m"
#define CLR_INT     "\033[90m"
#define CLR_UNK     "\033[91m"
#define CLR_HEX     "\033[90m"
#define CLR_NAME    "\033[1;37m"

static bool use_color = true;

static const char *c(const char *code) {
    return use_color ? code : "";
}

static void strip_ansi(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 1 < out_size; i++) {
        if (in[i] == '\033' && in[i + 1] == '[') {
            i += 2;
            while (in[i] && in[i] != 'm') i++;
            continue;
        }
        out[j++] = in[i];
    }
    out[j] = '\0';
}

static void out_printf(ViewerState *vs, const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    fputs(buf, stdout);
    if (vs->log_file) {
        char plain[2048];
        strip_ansi(buf, plain, sizeof(plain));
        fputs(plain, vs->log_file);
    }
}

static void out_flush(ViewerState *vs) {
    fflush(stdout);
    if (vs->log_file) fflush(vs->log_file);
}

static double now_seconds(void) {
    struct timespec ts;
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return (double)(t - 116444736000000000ULL) / 10000000.0;
#else
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
#endif
}

static void maybe_print_rate(ViewerState *vs) {
    if (!vs->show_rate) return;
    double now = now_seconds();
    if (vs->rate_last_time == 0.0) {
        vs->rate_last_time = now;
        vs->rate_last_count = vs->packet_count;
        return;
    }
    double delta = now - vs->rate_last_time;
    if (delta < 2.0) return;

    uint64_t diff = vs->packet_count - vs->rate_last_count;
    double rate = diff / delta;
    fprintf(stderr, "\033[90m[%.1f pkt/s, %llu total]\033[0m\n",
            rate, (unsigned long long)vs->packet_count);
    fflush(stderr);
    vs->rate_last_time = now;
    vs->rate_last_count = vs->packet_count;
}

void viewer_init(ViewerState *vs, uint16_t server_port) {
    memset(vs, 0, sizeof(*vs));
    vs->server_port = server_port;
    conn_table_init(&vs->connections);
    enable_ansi();
}

void viewer_free(ViewerState *vs) {
    conn_table_free(&vs->connections);
}

void viewer_set_color(bool enabled) {
    use_color = enabled;
}

void viewer_set_log_file(ViewerState *vs, FILE *f) {
    vs->log_file = f;
}

static void format_ip(uint32_t ip, char *buf, size_t buf_size) {
    snprintf(buf, buf_size, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}

static void format_time(double ts, char *buf, size_t buf_size) {
    int total_secs = (int)ts;
    int hours = (total_secs / 3600) % 24;
    int mins = (total_secs / 60) % 60;
    int secs = total_secs % 60;
    int millis = (int)((ts - (int)ts) * 1000);
    snprintf(buf, buf_size, "%02d:%02d:%02d.%03d", hours, mins, secs, millis);
}

static void print_hex(ViewerState *vs, const uint8_t *data, size_t len, size_t max_bytes) {
    out_printf(vs, "%s", c(CLR_HEX));
    size_t show = len < max_bytes ? len : max_bytes;
    for (size_t i = 0; i < show; i++) {
        out_printf(vs, "%02X ", data[i]);
    }
    if (len > max_bytes) out_printf(vs, "...");
    out_printf(vs, "%s", c(CLR_RESET));
}

static bool should_filter_rpc(ViewerState *vs, uint32_t rpc_id) {
    if (vs->rpc_filter_count == 0) return false;
    for (size_t i = 0; i < vs->rpc_filter_count; i++) {
        if (vs->rpc_filter[i] == rpc_id) return false;
    }
    return true;
}

static void print_message(ViewerState *vs, double timestamp, PacketDirection dir,
                           const char *client_ip, const IdentifiedMessage *msg) {
    char time_str[32];
    format_time(timestamp, time_str, sizeof(time_str));
    const char *dir_str = (dir == DIR_CLIENT_TO_SERVER) ? "C->S" : "S->C";
    const char *dir_clr = (dir == DIR_CLIENT_TO_SERVER) ? CLR_C2S : CLR_S2C;

    vs->packet_count++;

    switch (msg->type) {
        case MSG_RPC:
            if (should_filter_rpc(vs, msg->rpc_id)) return;
            out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %sRPC %-3u%s  %s%s%s",
                   c(CLR_TIME), time_str,
                   c(CLR_IP), client_ip,
                   c(dir_clr), dir_str, c(CLR_RESET),
                   c(CLR_RPC), msg->rpc_id, c(CLR_RESET),
                   c(CLR_NAME), msg->name, c(CLR_RESET));
            if (vs->show_hex && msg->payload_len > 0) {
                out_printf(vs, "  ");
                print_hex(vs, msg->payload, msg->payload_len, 32);
            }
            out_printf(vs, "\n");
            break;

        case MSG_PACKET:
            if (vs->hide_sync) return;
            out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %sPKT%s      %s%s%s",
                   c(CLR_TIME), time_str,
                   c(CLR_IP), client_ip,
                   c(dir_clr), dir_str, c(CLR_RESET),
                   c(CLR_SYNC), c(CLR_RESET),
                   c(CLR_SYNC), msg->name, c(CLR_RESET));
            if (vs->show_hex && msg->payload_len > 0) {
                out_printf(vs, "  ");
                print_hex(vs, msg->payload, msg->payload_len, 16);
            }
            out_printf(vs, "\n");
            break;

        case MSG_INTERNAL:
            out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %sINT      %s%s\n",
                   c(CLR_TIME), time_str,
                   c(CLR_IP), client_ip,
                   c(dir_clr), dir_str, c(CLR_RESET),
                   c(CLR_INT), msg->name, c(CLR_RESET));
            break;

        case MSG_UNKNOWN:
            out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %s???  0x%02X  %zu bytes%s",
                   c(CLR_TIME), time_str,
                   c(CLR_IP), client_ip,
                   c(dir_clr), dir_str, c(CLR_RESET),
                   c(CLR_UNK), msg->packet_id, msg->payload_len, c(CLR_RESET));
            if (vs->show_hex && msg->payload_len > 0) {
                out_printf(vs, "  ");
                print_hex(vs, msg->payload, msg->payload_len, 16);
            }
            out_printf(vs, "\n");
            break;
    }
    out_flush(vs);
}

static void process_reassembled(ViewerState *vs, double timestamp, PacketDirection dir,
                                 const char *client_ip,
                                 const uint8_t *data, size_t len) {
    IdentifiedMessage msg;
    if (identify_message(data, len, dir, &msg)) {
        print_message(vs, timestamp, dir, client_ip, &msg);
    }
}

void viewer_process_udp(ViewerState *vs, UdpPacket *pkt, uint8_t *work_buf, size_t work_size) {
    maybe_print_rate(vs);
    if (query_is_query_packet(pkt->data, pkt->data_len)) {
        QueryResult qr = query_decode(pkt->data, pkt->data_len);
        char time_str[32];
        format_time(pkt->timestamp, time_str, sizeof(time_str));
        char ip_str[32];
        uint32_t client_ip = (pkt->direction == DIR_CLIENT_TO_SERVER) ? pkt->src_ip : pkt->dst_ip;
        format_ip(client_ip, ip_str, sizeof(ip_str));
        const char *dir_str = (pkt->direction == DIR_CLIENT_TO_SERVER) ? "C->S" : "S->C";
        const char *dir_clr = (pkt->direction == DIR_CLIENT_TO_SERVER) ? CLR_C2S : CLR_S2C;
        vs->packet_count++;
        out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %sQRY      %s%s\n",
               c(CLR_TIME), time_str,
               c(CLR_IP), ip_str,
               c(dir_clr), dir_str, c(CLR_RESET),
               c(CLR_QUERY), qr.name, c(CLR_RESET));
        out_flush(vs);
        return;
    }

    uint32_t client_ip, client_port_val;
    if (pkt->direction == DIR_CLIENT_TO_SERVER) {
        client_ip = pkt->src_ip;
        client_port_val = pkt->src_port;
    } else {
        client_ip = pkt->dst_ip;
        client_port_val = pkt->dst_port;
    }

    char client_ip_str[32];
    format_ip(client_ip, client_ip_str, sizeof(client_ip_str));

    if (vs->client_filter[0] && strcmp(vs->client_filter, client_ip_str) != 0) return;

    Connection *conn = conn_table_get_or_create(&vs->connections, client_ip, (uint16_t)client_port_val);
    if (!conn) return;

    size_t data_len = pkt->data_len;
    if (data_len > work_size) return;
    memcpy(work_buf, pkt->data, data_len);

    if (pkt->direction == DIR_CLIENT_TO_SERVER) {
        if (!samp_decrypt(work_buf, data_len, vs->server_port)) {
            return;
        }
        data_len--;
    }

    if (pkt->direction == DIR_SERVER_TO_CLIENT) {
        if (omp_is_access_reply(work_buf, data_len)) {
            uint8_t key[4];
            if (omp_extract_key(work_buf, data_len, key)) {
                memcpy(conn->omp_key, key, 4);
                conn->has_omp_key = true;
                char time_str[32];
                format_time(pkt->timestamp, time_str, sizeof(time_str));
                vs->packet_count++;
                out_printf(vs, "%s%s  %s%-15s  %sS->C%s  %sOMP      KeyExchange%s\n",
                       c(CLR_TIME), time_str,
                       c(CLR_IP), client_ip_str,
                       c(CLR_S2C), c(CLR_RESET),
                       c(CLR_OMP), c(CLR_RESET));
                out_flush(vs);
            }
            return;
        }
        if (conn->has_omp_key) {
            omp_decrypt(work_buf, data_len, conn->omp_key);
        }
    }

    HandshakeResult hs = handshake_check(work_buf, data_len, conn->connected);
    if (hs.type != HS_NONE) {
        char time_str[32];
        format_time(pkt->timestamp, time_str, sizeof(time_str));
        const char *dir_str = (pkt->direction == DIR_CLIENT_TO_SERVER) ? "C->S" : "S->C";
        const char *dir_clr = (pkt->direction == DIR_CLIENT_TO_SERVER) ? CLR_C2S : CLR_S2C;
        vs->packet_count++;
        out_printf(vs, "%s%s  %s%-15s  %s%-4s%s  %sHSK      %s%s\n",
               c(CLR_TIME), time_str,
               c(CLR_IP), client_ip_str,
               c(dir_clr), dir_str, c(CLR_RESET),
               c(CLR_HS), hs.name, c(CLR_RESET));

        if (hs.type == HS_CONNECTION_REQUEST_ACCEPTED || hs.type == HS_NEW_INCOMING_CONNECTION) {
            if (!conn->connected) {
                conn->connected = true;
                conn->connect_time = pkt->timestamp;
                out_printf(vs, "%s         %s>>> %s connected%s\n",
                       c(CLR_TIME),
                       c(CLR_HS), client_ip_str, c(CLR_RESET));
            }
        }
        if (hs.type == HS_DISCONNECTION || hs.type == HS_CONNECTION_LOST) {
            if (conn->connected) {
                double duration = pkt->timestamp - conn->connect_time;
                out_printf(vs, "%s         %s<<< %s disconnected  (session %.1fs, %llu pkts C->S, %llu pkts S->C)%s\n",
                       c(CLR_TIME),
                       c(CLR_HS), client_ip_str,
                       duration,
                       (unsigned long long)conn->packets_c2s,
                       (unsigned long long)conn->packets_s2c,
                       c(CLR_RESET));
            }
            conn->connected = false;
        }
        out_flush(vs);
        return;
    }

    if (pkt->direction == DIR_CLIENT_TO_SERVER) conn->packets_c2s++;
    else conn->packets_s2c++;

    if (!conn->connected) return;

    uint8_t scratch[MAX_PACKET_SIZE];
    RakNetDatagram dgram;
    if (!raknet_parse_datagram(work_buf, data_len, &dgram, scratch, sizeof(scratch))) {
        return;
    }

    uint64_t ck = conn_key(client_ip, (uint16_t)client_port_val);
    DedupTracker *dedup = (pkt->direction == DIR_CLIENT_TO_SERVER)
                          ? &conn->dedup_c2s : &conn->dedup_s2c;

    for (size_t i = 0; i < dgram.packet_count; i++) {
        InternalPacket *ipkt = &dgram.packets[i];

        if (ipkt->reliability == RELIABLE || ipkt->reliability == RELIABLE_ORDERED ||
            ipkt->reliability == RELIABLE_SEQUENCED) {
            if (dedup_is_duplicate(dedup, ipkt->message_number)) continue;
        }

        if (ipkt->is_split) {
            size_t assembled_len;
            uint8_t *assembled = split_tracker_add(&vs->connections.splits, ck,
                                                   ipkt, &assembled_len);
            if (assembled) {
                process_reassembled(vs, pkt->timestamp, pkt->direction,
                                    client_ip_str, assembled, assembled_len);
                free(assembled);
            }
            continue;
        }

        process_reassembled(vs, pkt->timestamp, pkt->direction,
                            client_ip_str, ipkt->data, ipkt->data_len);
    }
}
