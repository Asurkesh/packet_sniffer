#include "print.h"
#include "../util/util.h"
#include <stdio.h>
#include <ctype.h>
#include <netinet/ip6.h>

// Глобальные переменные статистики (extern)
extern Stats stats;
extern IpStat ip_stats[];
extern int ip_stats_count;

void print_packet(const unsigned char *packet, int size, int datalink_type) {
    int ip_header_offset = get_ip_header_offset(datalink_type);
    int has_eth = 0;
    uint16_t ether_type = 0;

    // Время
    time_t rawtime;
    struct tm *timeinfo;
    char time_str[20];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(time_str, sizeof(time_str), "%H:%M:%S", timeinfo);
    printf("[%s] ", time_str);

    if (datalink_type == DLT_EN10MB) {
        // Ethernet
        if (size < 14) {
            printf("Пакет слишком короткий для Ethernet\n\n");
            return;
        }
        const struct ether_header *eth = (const struct ether_header *)packet;
        ether_type = ntohs(eth->ether_type);

        if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6 || ether_type == ETHERTYPE_ARP) {
            has_eth = 1;

            char src_mac[18], dst_mac[18];
            snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                    eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                    eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf(COLOR_MAC "MAC %s -> %s\n" COLOR_RESET, src_mac, dst_mac);
        }
    }

    // Обработка ARP
    if (has_eth && ether_type == ETHERTYPE_ARP) {
        if (size < ip_header_offset + sizeof(struct arphdr)) {
            printf("Пакет слишком короткий для ARP\n\n");
            return;
        }

        struct arphdr *arp_header = (struct arphdr *)(packet + ip_header_offset);
        unsigned char *arp_ptr = (unsigned char *)(packet + ip_header_offset + sizeof(struct arphdr));

        if (ntohs(arp_header->ar_hrd) == ARPHRD_ETHER && ntohs(arp_header->ar_pro) == ETHERTYPE_IP) {
            char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
            char sender_mac[18], target_mac[18];

            unsigned char *sender_mac_ptr = arp_ptr;
            unsigned char *sender_ip_ptr  = arp_ptr + 6;
            unsigned char *target_mac_ptr = arp_ptr + 10;
            unsigned char *target_ip_ptr  = arp_ptr + 16;

            snprintf(sender_mac, sizeof(sender_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    sender_mac_ptr[0], sender_mac_ptr[1], sender_mac_ptr[2],
                    sender_mac_ptr[3], sender_mac_ptr[4], sender_mac_ptr[5]);

            snprintf(target_mac, sizeof(target_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    target_mac_ptr[0], target_mac_ptr[1], target_mac_ptr[2],
                    target_mac_ptr[3], target_mac_ptr[4], target_mac_ptr[5]);

            inet_ntop(AF_INET, sender_ip_ptr, sender_ip, sizeof(sender_ip));
            inet_ntop(AF_INET, target_ip_ptr, target_ip, sizeof(target_ip));

            printf(COLOR_PROTO "[ARP] " COLOR_RESET);
            if (ntohs(arp_header->ar_op) == ARPOP_REQUEST) {
                printf("Запрос: кто имеет " COLOR_IP "%s" COLOR_RESET "? Скажите " COLOR_MAC "%s" COLOR_RESET "\n",
                    target_ip, sender_mac);
            } else if (ntohs(arp_header->ar_op) == ARPOP_REPLY) {
                printf("Ответ: " COLOR_IP "%s" COLOR_RESET " имеет MAC " COLOR_MAC "%s" COLOR_RESET "\n",
                    sender_ip, sender_mac);
            } else {
                printf("Неизвестная операция ARP\n");
            }
        } else {
            printf(COLOR_PROTO "[ARP] " COLOR_RESET "(неподдерживаемый формат)\n");
        }

        printf(COLOR_SIZE "Передан пакет размером [%d байт]" COLOR_RESET "\n\n", size);
        return;
    }

    // IPv4
    if ((has_eth && ether_type == ETHERTYPE_IP) || 
        (!has_eth && size > ip_header_offset && ((packet[ip_header_offset] >> 4) == 4))) {

        if (size < ip_header_offset + sizeof(struct iphdr)) {
            printf("Пакет слишком короткий для IPv4\n\n");
            return;
        }

        const struct iphdr *iph = (const struct iphdr *)(packet + ip_header_offset);
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(iph->daddr), dst_ip, sizeof(dst_ip));

        if (iph->protocol == IPPROTO_TCP) {
            if (size < ip_header_offset + iph->ihl * 4 + sizeof(struct tcphdr)) {
                printf("Пакет слишком короткий для TCP\n\n");
                return;
            }
            const struct tcphdr *tcph = (const struct tcphdr *)(packet + ip_header_offset + iph->ihl * 4);
            printf(COLOR_PROTO "[TCP] " COLOR_RESET);
            printf(COLOR_IP "%s:%s%d" COLOR_RESET " -> " COLOR_IP "%s:%s%d" COLOR_RESET,
                src_ip, COLOR_PORT, ntohs(tcph->source),
                dst_ip, COLOR_PORT, ntohs(tcph->dest));

            //
            printf("Флаг: ");
                if (tcph->th_flags & TH_SYN) printf("SYN ");
                if (tcph->th_flags & TH_ACK) printf("ACK ");
                if (tcph->th_flags & TH_FIN) printf("FIN ");
                if (tcph->th_flags & TH_RST) printf("RST ");
                if (tcph->th_flags & TH_PUSH) printf("PSH ");
                if (tcph->th_flags & TH_URG) printf("URG ");

            int payload_offset = get_tcp_payload_offset(packet, size, datalink_type);

            if (size > payload_offset) {
                const char *payload = (const char *)(packet + payload_offset);
                int plen = size - payload_offset;

                if (plen > 0 && isprint(payload[0])) {
                    printf(COLOR_HTTP "HTTP (порт %u -> %u): ", ntohs(tcph->th_sport), ntohs(tcph->th_dport));
                    for (int i = 0; i < plen && i < 200; i++) {
                        if (payload[i] == '\r' || payload[i] == '\n') break;
                        putchar(payload[i]);
                    }
                    printf("\n" COLOR_RESET);
                }
            }


        } else if (iph->protocol == IPPROTO_UDP) {
            if (size < ip_header_offset + iph->ihl * 4 + sizeof(struct udphdr)) {
                printf("Пакет слишком короткий для UDP\n\n");
                return;
            }
            const struct udphdr *udph = (const struct udphdr *)(packet + ip_header_offset + iph->ihl * 4);
            printf(COLOR_PROTO "[UDP] " COLOR_RESET);
            printf(COLOR_IP "%s:%s%d" COLOR_RESET " -> " COLOR_IP "%s:%s%d" COLOR_RESET,
                src_ip, COLOR_PORT, ntohs(udph->source),
                dst_ip, COLOR_PORT, ntohs(udph->dest));

            //
            uint16_t sport = ntohs(udph->uh_sport);
            uint16_t dport = ntohs(udph->uh_dport);
            if (sport == 53 || dport == 53) {
                print_dns(packet + ip_header_offset + iph->ihl * 4 + sizeof(struct udphdr),
                  size - ip_header_offset - iph->ihl * 4 - sizeof(struct udphdr));
            }

        } else {
            printf(COLOR_PROTO "[IPv4 протокол %d] " COLOR_RESET, iph->protocol);
            printf(COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, src_ip, dst_ip);
        }
    }
    // IPv6
    else if ((has_eth && ether_type == ETHERTYPE_IPV6) || 
            (!has_eth && size > ip_header_offset && ((packet[ip_header_offset] >> 4) == 6))) {

        if (size < ip_header_offset + sizeof(struct ip6_hdr)) {
            printf("Пакет слишком короткий для IPv6\n\n");
            return;
        }

        struct ip6_hdr *ip6h = (struct ip6_hdr *)(packet + ip_header_offset);
        char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6h->ip6_src), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst_ip, sizeof(dst_ip));
        printf(COLOR_PROTO "[IPv6] " COLOR_RESET);
        printf(COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, src_ip, dst_ip);


    } else {
        printf(COLOR_PROTO "[Неизвестный протокол]" COLOR_RESET);
    }

    printf(" " COLOR_SIZE "Передан пакет размером [%d байт]" COLOR_RESET "\n\n", size);
}


void print_dns(const unsigned char *dns_data, int dns_size) {
    // Заголовок DNS
    struct dnshdr {
        uint16_t id;
        uint16_t flags;
        uint16_t qdcount;
        uint16_t ancount;
        uint16_t nscount;
        uint16_t arcount;
    };
    
    if (dns_size < sizeof(struct dnshdr)) {
        printf("DNS пакет слишком мал\n");
        return;
    }

    const struct dnshdr *dns_header = (const struct dnshdr *)dns_data;

    uint16_t flags = ntohs(dns_header->flags);

    int qr = (flags >> 15) & 0x1; // 0 - запрос, 1 - ответ

    printf(" [DNS %s] ID: %u, Вопросов: %u, Ответов: %u\n",
        qr ? "ответ" : "запрос",
        ntohs(dns_header->id),
        ntohs(dns_header->qdcount),
        ntohs(dns_header->ancount));
}

