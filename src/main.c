#include "common.h"
#include "pcap_reader.h"
#include "pipeline.h"
#include <signal.h>

static volatile int running = 1;

static void on_sigint(int sig) {
    (void)sig;
    running = 0;
}

static void print_usage(const char *prog) {
    fprintf(stderr,
        "omp-packet-viewer - live SA-MP / open.mp packet decoder\n\n"
        "Usage:\n"
        "  %s -f <pcap-file> [-p <port>] [options]\n"
        "  %s -i <interface> [-p <port>] [options]\n\n"
        "Options:\n"
        "  -f <file>       Read from a .pcap capture file\n"
        "  -i <iface>      Capture live traffic from a network interface\n"
        "  -p <port>       Server port (default: 7777)\n"
        "  --hide-sync     Suppress sync packets (they're ~95%% of traffic)\n"
        "  --hex           Print hex dump of each payload\n"
        "  --rpc <ids>     Only show these RPC IDs (comma-separated, e.g. 25,128)\n"
        "  --client <ip>   Only show traffic for one client IP\n"
        "  --bpf <expr>    Custom BPF filter (overrides default 'udp port N')\n"
        "  --log <path>    Mirror output to a log file (ANSI stripped)\n"
        "  --no-color      Disable colored output\n"
        "  -h, --help      Show this help\n\n"
        "Examples:\n"
        "  %s -f session.pcap --hide-sync\n"
        "  %s -i eth0 -p 7777 --rpc 25,93 --hex\n",
        prog, prog, prog, prog);
}

static void parse_rpc_filter(const char *arg, ViewerState *vs) {
    char buf[512];
    strncpy(buf, arg, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *tok = strtok(buf, ",");
    while (tok && vs->rpc_filter_count < 256) {
        vs->rpc_filter[vs->rpc_filter_count++] = (uint32_t)atoi(tok);
        tok = strtok(NULL, ",");
    }
}

int main(int argc, char *argv[]) {
    const char *pcap_file = NULL;
    const char *iface = NULL;
    uint16_t server_port = 7777;
    bool hide_sync = false;
    bool show_hex = false;
    bool color = true;
    const char *rpc_filter_str = NULL;
    const char *client_filter = NULL;
    const char *bpf = NULL;
    const char *log_path = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0 && i + 1 < argc) {
            pcap_file = argv[++i];
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            iface = argv[++i];
        } else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            server_port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--hide-sync") == 0) {
            hide_sync = true;
        } else if (strcmp(argv[i], "--hex") == 0) {
            show_hex = true;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            color = false;
        } else if (strcmp(argv[i], "--rpc") == 0 && i + 1 < argc) {
            rpc_filter_str = argv[++i];
        } else if (strcmp(argv[i], "--client") == 0 && i + 1 < argc) {
            client_filter = argv[++i];
        } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
            bpf = argv[++i];
        } else if (strcmp(argv[i], "--log") == 0 && i + 1 < argc) {
            log_path = argv[++i];
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!pcap_file && !iface) {
        fprintf(stderr, "Error: need either -f <pcap-file> or -i <interface>\n\n");
        print_usage(argv[0]);
        return 1;
    }

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    signal(SIGINT, on_sigint);

    PcapReader reader;
    bool ok;
    if (pcap_file) {
        ok = pcap_reader_open_file(&reader, pcap_file, server_port);
    } else {
        ok = pcap_reader_open_live(&reader, iface, server_port, bpf);
    }
    if (!ok) return 1;

    ViewerState vs;
    viewer_init(&vs, server_port);
    viewer_set_color(color);
    vs.hide_sync = hide_sync;
    vs.show_hex = show_hex;
    if (rpc_filter_str) parse_rpc_filter(rpc_filter_str, &vs);
    if (client_filter) {
        strncpy(vs.client_filter, client_filter, sizeof(vs.client_filter) - 1);
    }

    FILE *log_file = NULL;
    if (log_path) {
        log_file = fopen(log_path, "w");
        if (!log_file) {
            fprintf(stderr, "warning: could not open log file %s\n", log_path);
        } else {
            viewer_set_log_file(&vs, log_file);
        }
    }

    fprintf(stderr, "omp-packet-viewer | port %u", server_port);
    if (pcap_file) fprintf(stderr, " | reading %s", pcap_file);
    if (iface)     fprintf(stderr, " | live on %s", iface);
    if (hide_sync) fprintf(stderr, " | sync hidden");
    if (rpc_filter_str) fprintf(stderr, " | rpc filter: %s", rpc_filter_str);
    if (client_filter)  fprintf(stderr, " | client: %s", client_filter);
    fprintf(stderr, "\n");
    if (iface) fprintf(stderr, "Press Ctrl+C to stop.\n");
    fprintf(stderr, "\n");

    uint8_t pkt_buf[MAX_PACKET_SIZE];
    uint8_t work_buf[MAX_PACKET_SIZE];
    UdpPacket pkt;

    while (running && pcap_reader_next(&reader, &pkt, pkt_buf, sizeof(pkt_buf))) {
        viewer_process_udp(&vs, &pkt, work_buf, sizeof(work_buf));
    }

    fprintf(stderr, "\n%llu packets decoded.\n", (unsigned long long)vs.packet_count);

    pcap_reader_close(&reader);
    viewer_free(&vs);
    if (log_file) fclose(log_file);

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
