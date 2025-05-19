#include "util.h"
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
// Реализация простых вспомогательных функций

int get_ip_header_offset(int datalink_type) {
    switch (datalink_type) {
        case DLT_EN10MB:      // Ethernet
            return 14;
        case DLT_NULL:        // Loopback (old BSD)
        case DLT_LOOP:        // Loopback (Linux)
            return 4;
        case DLT_LINUX_SLL:   // Linux cooked capture (any)
            return 16;
        default:
            return 0;  // Неизвестный — будем считать без смещения
    }
}

int compare_by_bytes_desc(const void *a, const void *b) {
    const IpStat *statA = (const IpStat *)a;
    const IpStat *statB = (const IpStat *)b;
    if (statB->total_bytes > statA->total_bytes) return 1;
    if (statB->total_bytes < statA->total_bytes) return -1;
    return 0;
}

int get_tcp_payload_offset(const unsigned char *packet, int size, int datalink_type) {
    int offset = get_ip_header_offset(datalink_type);
    if (size < offset + 1) return -1;

    uint8_t version = (packet[offset] >> 4);
    if (version == 4) {
        if (size < offset + sizeof(struct iphdr)) return -1;
        const struct iphdr *iph = (const struct iphdr *)(packet + offset);
        if (iph->protocol != IPPROTO_TCP) return -1;

        int ip_header_len = iph->ihl * 4;
        if (size < offset + ip_header_len + sizeof(struct tcphdr)) return -1;

        const struct tcphdr *tcph = (const struct tcphdr *)(packet + offset + ip_header_len);
        int tcp_header_len = tcph->doff * 4;

        return offset + ip_header_len + tcp_header_len;
    }
    return -1;
}