#ifndef OMP_COMMON_H
#define OMP_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

typedef enum {
    DIR_CLIENT_TO_SERVER,
    DIR_SERVER_TO_CLIENT
} PacketDirection;

typedef struct {
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    PacketDirection direction;
    uint16_t server_port;
    double timestamp;
    const uint8_t *data;
    size_t data_len;
} UdpPacket;

#define MAX_PACKET_SIZE 65536

#endif
