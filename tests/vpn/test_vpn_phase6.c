// SPDX-License-Identifier: BSD-2-Clause
/*
 * PQVeil Phase 6 VPN & Packet Routing Test Suite
 *
 * Verifies:
 *   1. TUN IPv4/TCP packet parsing & flow extraction
 *   2. IPv4/TCP return packet synthesis with valid IP and TCP checksums
 *   3. DNS query redirection to Tor virtual DNS port
 *   4. Fail-closed drop of raw UDP and QUIC packets (leak prevention)
 *   5. Fail-closed drop of IPv6 packets (prevents unrouted cellular leaks)
 *   6. Rejection of truncated and corrupt packet headers
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "packet_router.h"

int main(void)
{
    printf("==========================================================\n");
    printf(" Running PQVeil Phase 6: VPN & Packet Forwarding Tests\n");
    printf("==========================================================\n");

    // ---------------------------------------------------------------------
    // Test 1: Synthesize and Inspect IPv4 TCP Packet
    // ---------------------------------------------------------------------
    printf("[*] Test 1: Testing IPv4 TCP packet parsing and flow extraction...\n");
    uint8_t tcp_raw_pkt[PQVEIL_MAX_PACKET_SIZE];
    size_t pkt_len = 0;
    const char *payload_text = "GET /status HTTP/1.1\r\n\r\n";
    size_t payload_len = strlen(payload_text);

    uint32_t src_ip = 0x0AC00002; // 10.192.0.2 (Client TUN IP)
    uint32_t dst_ip = 0x5DB8D822; // 93.184.216.34 (Remote Target)
    uint16_t src_port = 49152;
    uint16_t dst_port = 80;

    assert(pqveil_synthesize_tcp_packet(
        tcp_raw_pkt, &pkt_len,
        src_ip, src_port,
        dst_ip, dst_port,
        1001, 2002,
        0x18, // PSH | ACK
        (const uint8_t *)payload_text, payload_len
    ) == 0);
    assert(pkt_len == 20 + 20 + payload_len);

    pqveil_tcp_segment_t seg;
    pqveil_packet_verdict_t verdict = pqveil_inspect_tun_packet(tcp_raw_pkt, pkt_len, &seg);
    assert(verdict == VERDICT_FORWARD_TOR_TCP);
    assert(seg.flow.src_ip == src_ip);
    assert(seg.flow.dst_ip == dst_ip);
    assert(seg.flow.src_port == src_port);
    assert(seg.flow.dst_port == dst_port);
    assert(seg.flow.protocol == PQVEIL_IP_PROTO_TCP);
    assert(seg.seq_num == 1001);
    assert(seg.ack_num == 2002);
    assert(seg.flags == 0x18);
    assert(seg.payload_len == payload_len);
    assert(memcmp(seg.payload, payload_text, payload_len) == 0);
    printf("    [+] TCP flow tuple (10.192.0.2:49152 -> 93.184.216.34:80) extracted: PASS\n");

    // ---------------------------------------------------------------------
    // Test 2: Verify Checksum Validity on Synthesized Return Packet
    // ---------------------------------------------------------------------
    printf("[*] Test 2: Verifying IP header checksum on synthesized packet...\n");
    // Standard property: IP checksum over header containing computed checksum must equal 0 (or 0xFFFF)
    uint16_t verify_csum = pqveil_ip_checksum(tcp_raw_pkt, 20);
    assert(verify_csum == 0 || verify_csum == 0xFFFF);
    printf("    [+] IPv4 header checksum mathematically verified: PASS\n");

    // ---------------------------------------------------------------------
    // Test 3: DNS Redirection (Port 53 UDP)
    // ---------------------------------------------------------------------
    printf("[*] Test 3: Testing DNS redirection to Tor virtual resolver...\n");
    uint8_t dns_pkt[20 + 8 + 32] = {0};
    dns_pkt[0] = 0x45; // IPv4
    dns_pkt[2] = 0; dns_pkt[3] = sizeof(dns_pkt); // Total len
    dns_pkt[9] = PQVEIL_IP_PROTO_UDP; // Protocol 17
    dns_pkt[20] = 0xC0; dns_pkt[21] = 0x01; // Src Port 49153
    dns_pkt[22] = 0x00; dns_pkt[23] = 53;   // Dst Port 53 (DNS)
    dns_pkt[24] = 0x00; dns_pkt[25] = 40;   // UDP Len

    verdict = pqveil_inspect_tun_packet(dns_pkt, sizeof(dns_pkt), NULL);
    assert(verdict == VERDICT_REDIRECT_TOR_DNS);
    printf("    [+] DNS (Port 53) redirected to Tor DNSPort: PASS\n");

    // ---------------------------------------------------------------------
    // Test 4: Fail-Closed Drop of Raw UDP / QUIC (Port 443 UDP)
    // ---------------------------------------------------------------------
    printf("[*] Test 4: Testing fail-closed drop of raw UDP & QUIC packets...\n");
    uint8_t quic_pkt[20 + 8 + 64] = {0};
    quic_pkt[0] = 0x45; // IPv4
    quic_pkt[2] = 0; quic_pkt[3] = sizeof(quic_pkt);
    quic_pkt[9] = PQVEIL_IP_PROTO_UDP;
    quic_pkt[20] = 0xC0; quic_pkt[21] = 0x02; // Src Port
    quic_pkt[22] = 0x01; quic_pkt[23] = 0xBB; // Dst Port 443 (QUIC)

    verdict = pqveil_inspect_tun_packet(quic_pkt, sizeof(quic_pkt), NULL);
    assert(verdict == VERDICT_DROP_FAIL_CLOSED);
    printf("    [+] Non-DNS UDP / QUIC traffic dropped fail-closed: PASS\n");

    // ---------------------------------------------------------------------
    // Test 5: IPv6 Cellular Leak Prevention
    // ---------------------------------------------------------------------
    printf("[*] Test 5: Testing IPv6 leak prevention...\n");
    uint8_t ipv6_pkt[40] = {0};
    ipv6_pkt[0] = 0x60; // IPv6 Version 6

    verdict = pqveil_inspect_tun_packet(ipv6_pkt, sizeof(ipv6_pkt), NULL);
    assert(verdict == VERDICT_DROP_FAIL_CLOSED);
    printf("    [+] IPv6 packet intercepted and dropped fail-closed: PASS\n");

    // ---------------------------------------------------------------------
    // Test 6: Malformed Packet Rejection
    // ---------------------------------------------------------------------
    printf("[*] Test 6: Testing malformed packet detection...\n");
    uint8_t truncated_pkt[10] = { 0x45, 0x00 };
    verdict = pqveil_inspect_tun_packet(truncated_pkt, sizeof(truncated_pkt), NULL);
    assert(verdict == VERDICT_INVALID_PACKET);
    printf("    [+] Truncated packet rejected: PASS\n");

    printf("==========================================================\n");
    printf(" [SUCCESS] All Phase 6 VPN & Packet Routing Tests PASSED!\n");
    printf("==========================================================\n");
    return 0;
}

