/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * PQVeil Packet Routing & Userspace TCP/IP Engine
 *
 * Implements:
 *   - TUN interface IP packet parsing (IPv4 / IPv6)
 *   - TCP flow extraction & SOCKS5 stream multiplexing
 *   - DNS redirection to Tor DNSPort (5353)
 *   - Strict fail-closed policy: non-DNS UDP & QUIC drop
 *   - IP/TCP packet synthesis for incoming Tor return traffic
 */

#ifndef PQVEIL_PACKET_ROUTER_H
#define PQVEIL_PACKET_ROUTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define PQVEIL_MAX_PACKET_SIZE 1500

/* IP Protocol Numbers */
#define PQVEIL_IP_PROTO_TCP  6
#define PQVEIL_IP_PROTO_UDP  17
#define PQVEIL_IP_PROTO_ICMP 1

/* Routing Verdicts */
typedef enum {
    VERDICT_FORWARD_TOR_TCP, // Forward flow via Tor SOCKS5 to gateway
    VERDICT_REDIRECT_TOR_DNS,// Redirect DNS to Tor virtual DNSPort
    VERDICT_DROP_FAIL_CLOSED,// Block packet (raw UDP, QUIC, leak attempt)
    VERDICT_INVALID_PACKET   // Malformed header, corrupt checksum
} pqveil_packet_verdict_t;

/* 5-tuple flow identifier */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
} pqveil_flow_tuple_t;

/* Extracted TCP Segment Info */
typedef struct {
    pqveil_flow_tuple_t flow;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  flags; // SYN, ACK, FIN, RST, PSH
    const uint8_t *payload;
    size_t payload_len;
} pqveil_tcp_segment_t;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parses a raw IP packet read from the TUN interface.
 * Returns the routing verdict and populates flow / segment metadata.
 */
pqveil_packet_verdict_t pqveil_inspect_tun_packet(
    const uint8_t *packet,
    size_t packet_len,
    pqveil_tcp_segment_t *tcp_out
);

/**
 * Synthesizes a raw IPv4/TCP return packet to be written into the TUN interface.
 */
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
    size_t payload_len
);

/**
 * Computes standard Internet 16-bit One's Complement Checksum.
 */
uint16_t pqveil_ip_checksum(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PQVEIL_PACKET_ROUTER_H */

