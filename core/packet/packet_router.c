// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Packet Routing & Userspace TCP/IP Engine Implementation
 */

#include "packet_router.h"
#include <string.h>
#include <arpa/inet.h>

uint16_t pqveil_ip_checksum(const void *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }

    if (len == 1) {
        sum += *(const uint8_t *)p;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

pqveil_packet_verdict_t pqveil_inspect_tun_packet(
    const uint8_t *packet,
    size_t packet_len,
    pqveil_tcp_segment_t *tcp_out)
{
    if (!packet || packet_len < 20) {
        return VERDICT_INVALID_PACKET;
    }

    uint8_t ip_version = (packet[0] >> 4) & 0x0F;

    // IPv6 Handling: Block and fail-closed to prevent leaks in v1
    if (ip_version == 6) {
        return VERDICT_DROP_FAIL_CLOSED;
    }

    if (ip_version != 4) {
        return VERDICT_INVALID_PACKET;
    }

    size_t ihl = (packet[0] & 0x0F) * 4;
    if (ihl < 20 || packet_len < ihl) {
        return VERDICT_INVALID_PACKET;
    }

    uint16_t total_len = ((uint16_t)packet[2] << 8) | packet[3];
    if (packet_len < total_len) {
        return VERDICT_INVALID_PACKET;
    }

    uint8_t protocol = packet[9];
    uint32_t src_ip = ((uint32_t)packet[12] << 24) | ((uint32_t)packet[13] << 16) |
                      ((uint32_t)packet[14] << 8) | (uint32_t)packet[15];
    uint32_t dst_ip = ((uint32_t)packet[16] << 24) | ((uint32_t)packet[17] << 16) |
                      ((uint32_t)packet[18] << 8) | (uint32_t)packet[19];

    // 1. TCP Traffic: Extract Segment & Flow Tuple
    if (protocol == PQVEIL_IP_PROTO_TCP) {
        if (packet_len < ihl + 20) {
            return VERDICT_INVALID_PACKET;
        }

        const uint8_t *tcp_hdr = packet + ihl;
        uint16_t src_port = ((uint16_t)tcp_hdr[0] << 8) | tcp_hdr[1];
        uint16_t dst_port = ((uint16_t)tcp_hdr[2] << 8) | tcp_hdr[3];
        uint32_t seq = ((uint32_t)tcp_hdr[4] << 24) | ((uint32_t)tcp_hdr[5] << 16) |
                       ((uint32_t)tcp_hdr[6] << 8) | (uint32_t)tcp_hdr[7];
        uint32_t ack = ((uint32_t)tcp_hdr[8] << 24) | ((uint32_t)tcp_hdr[9] << 16) |
                       ((uint32_t)tcp_hdr[10] << 8) | (uint32_t)tcp_hdr[11];

        size_t tcp_offset = ((tcp_hdr[12] >> 4) & 0x0F) * 4;
        if (tcp_offset < 20 || packet_len < ihl + tcp_offset) {
            return VERDICT_INVALID_PACKET;
        }

        uint8_t flags = tcp_hdr[13];

        if (tcp_out) {
            tcp_out->flow.src_ip = src_ip;
            tcp_out->flow.dst_ip = dst_ip;
            tcp_out->flow.src_port = src_port;
            tcp_out->flow.dst_port = dst_port;
            tcp_out->flow.protocol = PQVEIL_IP_PROTO_TCP;
            tcp_out->seq_num = seq;
            tcp_out->ack_num = ack;
            tcp_out->flags = flags;
            tcp_out->payload = packet + ihl + tcp_offset;
            tcp_out->payload_len = total_len - (ihl + tcp_offset);
        }

        return VERDICT_FORWARD_TOR_TCP;
    }

    // 2. UDP Traffic: Only DNS (Port 53) permitted; All other UDP/QUIC blocked
    if (protocol == PQVEIL_IP_PROTO_UDP) {
        if (packet_len < ihl + 8) {
            return VERDICT_INVALID_PACKET;
        }
        const uint8_t *udp_hdr = packet + ihl;
        uint16_t dst_port = ((uint16_t)udp_hdr[2] << 8) | udp_hdr[3];

        if (dst_port == 53) {
            return VERDICT_REDIRECT_TOR_DNS;
        }

        // Raw UDP / QUIC on other ports dropped as per fail-closed policy
        return VERDICT_DROP_FAIL_CLOSED;
    }

    // All other protocols (ICMP, IGMP, etc.) dropped fail-closed
    return VERDICT_DROP_FAIL_CLOSED;
}

int pqveil_synthesize_tcp_packet(
    uint8_t *packet_out,
    size_t *packet_len,
    uint32_t src_ip,
    uint16_t src_port,
    uint32_t dst_ip,
    uint16_t dst_port,
    uint32_t seq,
    uint32_t ack,
    uint8_t flags,
    const uint8_t *payload,
    size_t payload_len)
{
    if (!packet_out || !packet_len) return -1;

    size_t total_len = 20 + 20 + payload_len; // 20B IPv4 + 20B TCP + Payload
    if (total_len > PQVEIL_MAX_PACKET_SIZE) return -2;

    memset(packet_out, 0, total_len);

    // 1. Build IPv4 Header (20 Bytes)
    packet_out[0] = 0x45; // Version 4, IHL 5
    packet_out[1] = 0x00; // DSCP / ECN
    packet_out[2] = (uint8_t)(total_len >> 8);
    packet_out[3] = (uint8_t)(total_len & 0xFF);
    packet_out[4] = 0x12; // Identification
    packet_out[5] = 0x34;
    packet_out[6] = 0x40; // Don't Fragment (DF)
    packet_out[7] = 0x00;
    packet_out[8] = 64;   // TTL
    packet_out[9] = PQVEIL_IP_PROTO_TCP; // Protocol 6
    // Checksum at [10..11] populated below

    // Source IP
    packet_out[12] = (uint8_t)(src_ip >> 24);
    packet_out[13] = (uint8_t)(src_ip >> 16);
    packet_out[14] = (uint8_t)(src_ip >> 8);
    packet_out[15] = (uint8_t)(src_ip & 0xFF);

    // Dest IP
    packet_out[16] = (uint8_t)(dst_ip >> 24);
    packet_out[17] = (uint8_t)(dst_ip >> 16);
    packet_out[18] = (uint8_t)(dst_ip >> 8);
    packet_out[19] = (uint8_t)(dst_ip & 0xFF);

    uint16_t ip_csum = pqveil_ip_checksum(packet_out, 20);
    packet_out[10] = (uint8_t)(ip_csum & 0xFF);
    packet_out[11] = (uint8_t)(ip_csum >> 8);

    // 2. Build TCP Header (20 Bytes) at offset 20
    uint8_t *tcp = packet_out + 20;
    tcp[0] = (uint8_t)(src_port >> 8);
    tcp[1] = (uint8_t)(src_port & 0xFF);
    tcp[2] = (uint8_t)(dst_port >> 8);
    tcp[3] = (uint8_t)(dst_port & 0xFF);

    tcp[4] = (uint8_t)(seq >> 24);
    tcp[5] = (uint8_t)(seq >> 16);
    tcp[6] = (uint8_t)(seq >> 8);
    tcp[7] = (uint8_t)(seq & 0xFF);

    tcp[8] = (uint8_t)(ack >> 24);
    tcp[9] = (uint8_t)(ack >> 16);
    tcp[10] = (uint8_t)(ack >> 8);
    tcp[11] = (uint8_t)(ack & 0xFF);

    tcp[12] = 0x50; // Data offset 5 (20 bytes)
    tcp[13] = flags;
    tcp[14] = 0xFF; // Window Size (65535)
    tcp[15] = 0xFF;
    // Checksum at [16..17]
    tcp[18] = 0x00; // Urgent Pointer
    tcp[19] = 0x00;

    // 3. Copy Payload
    if (payload && payload_len > 0) {
        memcpy(packet_out + 40, payload, payload_len);
    }

    // 4. Compute TCP Checksum with Pseudo-Header
    uint32_t tcp_len = (uint32_t)(20 + payload_len);
    uint8_t pseudo[12];
    memcpy(pseudo, packet_out + 12, 8); // src & dst ip
    pseudo[8] = 0;
    pseudo[9] = PQVEIL_IP_PROTO_TCP;
    pseudo[10] = (uint8_t)(tcp_len >> 8);
    pseudo[11] = (uint8_t)(tcp_len & 0xFF);

    uint32_t sum = 0;
    const uint16_t *p16 = (const uint16_t *)pseudo;
    for (int i = 0; i < 6; i++) sum += *p16++;

    p16 = (const uint16_t *)tcp;
    size_t rem = tcp_len;
    while (rem > 1) {
        sum += *p16++;
        rem -= 2;
    }
    if (rem == 1) {
        sum += *(const uint8_t *)p16;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t tcp_csum = (uint16_t)(~sum);
    tcp[16] = (uint8_t)(tcp_csum & 0xFF);
    tcp[17] = (uint8_t)(tcp_csum >> 8);

    *packet_len = total_len;
    return 0;
}

