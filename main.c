#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>

// Ethernet и ARP
#include <net/ethernet.h>       // ETH_P_*, struct ether_header
#include <net/if_arp.h>

// IPv4 / IPv6
#include <netinet/ip.h>         // struct iphdr
#include <netinet/ip6.h>        // struct ip6_hdr
#include <netinet/ip_icmp.h>    // struct icmphdr

// TCP/UDP
#include <netinet/tcp.h>        // struct tcphdr
#include <netinet/udp.h>        // struct udphdr

// Дубликат для struct ether_header (если <net/ethernet.h> не хватает)
#include <netinet/if_ether.h>   // struct ether_header, ETHERTYPE_IP

#ifndef TH_FIN
#define TH_FIN  0x01
#endif
#ifndef TH_SYN
#define TH_SYN  0x02
#endif
#ifndef TH_RST
#define TH_RST  0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK  0x10
#endif
#ifndef TH_URG
#define TH_URG  0x20
#endif
#ifndef TH_ECE
#define TH_ECE  0x40
#endif
#ifndef TH_CWR
#define TH_CWR  0x80
#endif


#define COLOR_RESET "\033[0m"
#define COLOR_PROTO "\033[1;34m"
#define COLOR_IP    "\033[1;32m"
#define COLOR_PORT  "\033[1;33m"
#define COLOR_SIZE  "\033[1;35m"
#define COLOR_MAC "\033[1;36m"
#define COLOR_DNS "\033[1;37m"
#define COLOR_HTTP "\033[1;40m"
#define COLOR_ICMP "\033[1;38m"
#define MAX_IPS 1000

typedef struct {
    unsigned long total_packets;
    unsigned long tcp_count;
    unsigned long udp_count;
    unsigned long arp_count;
    unsigned long ipv6_count;
    unsigned long other_count;
} Stats;
Stats stats = {0};

typedef struct {
    char ip[INET_ADDRSTRLEN];
    unsigned long total;
    unsigned long tcp;
    unsigned long udp;
    unsigned long other;
} IPStat;
IPStat ip_stats[MAX_IPS];
int ip_stats_count = 0;

pcap_t *handle = NULL;

void signal_handler(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

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

            if ((ntohs(tcph->th_dport) == 80 || ntohs(tcph->th_sport) == 80 ||
                ntohs(tcph->th_dport) == 8080 || ntohs(tcph->th_sport) == 8080) &&
                size > payload_offset) {

                const char *payload = (const char *)(packet + payload_offset);
                int plen = size - payload_offset;

                if (plen > 0 && isprint(payload[0])) {
                    printf(COLOR_HTTP "HTTP: ");
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


void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    int datalink_type = *(int *)args;
    stats.total_packets++;
    const struct ether_header *eth_header = (struct ether_header *)packet;
    u_short ether_type = ntohs(eth_header->ether_type);

    if (ether_type == ETHERTYPE_IP) {
        const struct ip *ip_hdr = (struct ip *)(packet + 14);
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_hdr->ip_src), src_ip, INET_ADDRSTRLEN);

        update_ip_stat(src_ip, ip_hdr->ip_p);

        if (ip_hdr->ip_p == IPPROTO_TCP)
            stats.tcp_count++;
        else if (ip_hdr->ip_p == IPPROTO_UDP)
            stats.udp_count++;
        else
            stats.other_count++;
    } else if (ether_type == ETHERTYPE_IPV6) {
        stats.ipv6_count++;
    } else if (ether_type == ETHERTYPE_ARP) {
        stats.arp_count++;
    } else {
        stats.other_count++;
    }
    print_packet(packet, header->len, datalink_type);

}

char *select_interface() {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Ошибка pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    printf("Выберите сетевой интерфейс:\n");
    int i = 1;
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next, i++) {
        printf("%d. %s", i, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    printf("Ваш выбор: ");
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice >= i) {
        printf("Неверный выбор\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    pcap_if_t *d = alldevs;
    for (int j = 1; j < choice; j++)
        d = d->next;

    char *iface = strdup(d->name);
    pcap_freealldevs(alldevs);
    return iface;
}


int main_menu() {
    printf("\nМеню:\n");
    printf("1. Слушать все пакеты\n");
    printf("2. Фильтрация по протоколу и порту\n");
    printf("3. Показать статистику\n");
    printf("4. Выход\n");
    printf("Ваш выбор: ");
    int choice;
    if (scanf("%d", &choice) != 1) {
        while(getchar() != '\n');
        return 0;
    }
    return choice;
}

void filter_menu(char *protocol_buf, int *port) {
    printf("Выберите протокол:\n");
    printf("1. TCP\n");
    printf("2. UDP\n");
    printf("Ваш выбор: ");
    int proto_choice;
    if (scanf("%d", &proto_choice) != 1 || (proto_choice != 1 && proto_choice != 2)) {
        strcpy(protocol_buf, "tcp");
    } else {
        strcpy(protocol_buf, proto_choice == 1 ? "tcp" : "udp");
    }
    printf("Введите порт (0 - все порты): ");
    if (scanf("%d", port) != 1 || *port < 0 || *port > 65535) {
        *port = 0;
    }
}

void start_sniffer(const char *iface, const char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live(iface, 65535, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Не удалось открыть интерфейс %s: %s\n", iface, errbuf);
        return;
    }

    int datalink_type = pcap_datalink(handle);

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Ошибка компиляции фильтра: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Ошибка установки фильтра: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }

    pcap_freecode(&fp);

    printf("\n" COLOR_PROTO "Сниффер запущен на интерфейсе %s с фильтром: %s\n" COLOR_RESET, iface, filter_exp);
    printf("Нажмите Ctrl+C для выхода в меню\n");

    signal(SIGINT, signal_handler);

    // Передаём указатель на datalink_type в качестве args
    pcap_loop(handle, -1, packet_handler, (unsigned char *)&datalink_type);

    pcap_close(handle);
    handle = NULL;
}

int main() {
    while (1) {
        int choice = main_menu();
        if (choice == 4) {
            printf("Выход...\n");
            break;
        }

        char *iface = select_interface();

        if (choice == 1) {
            start_sniffer(iface, "tcp or udp");
        } else if (choice == 2) {
            char protocol[4] = "tcp";
            int port = 0;
            filter_menu(protocol, &port);

            char filter_exp[64];
            if (port == 0)
                snprintf(filter_exp, sizeof(filter_exp), "%s", protocol);
            else
                snprintf(filter_exp, sizeof(filter_exp), "%s port %d", protocol, port);

            start_sniffer(iface, filter_exp);
        } else if (choice == 3) {
            print_statistics();
        } else {
            printf("Неверный выбор\n");
        }

        free(iface);
    }
    return 0;
}

void print_statistics() {
    printf("\n===== Общая статистика =====\n");
    printf("Всего пакетов: %lu\n", stats.total_packets);
    printf("TCP:            %lu\n", stats.tcp_count);
    printf("UDP:            %lu\n", stats.udp_count);
    printf("ARP:            %lu\n", stats.arp_count);
    printf("IPv6:           %lu\n", stats.ipv6_count);
    printf("Другое:         %lu\n", stats.other_count);

    printf("\n===== Статистика по IP =====\n");
    for (int i = 0; i < ip_stats_count; ++i) {
        printf("IP %s:\n", ip_stats[i].ip);
        printf("  Всего пакетов: %lu\n", ip_stats[i].total);
        printf("  TCP:           %lu\n", ip_stats[i].tcp);
        printf("  UDP:           %lu\n", ip_stats[i].udp);
        printf("  Другое:        %lu\n", ip_stats[i].other);
    }
    printf("=============================\n");
}


void update_ip_stat(const char *ip, u_char protocol) {
    for (int i = 0; i < ip_stats_count; ++i) {
        if (strcmp(ip_stats[i].ip, ip) == 0) {
            ip_stats[i].total++;
            if (protocol == IPPROTO_TCP)
                ip_stats[i].tcp++;
            else if (protocol == IPPROTO_UDP)
                ip_stats[i].udp++;
            else
                ip_stats[i].other++;
            return;
        }
    }
    if (ip_stats_count < MAX_IPS) {
        strncpy(ip_stats[ip_stats_count].ip, ip, INET_ADDRSTRLEN - 1);
        ip_stats[ip_stats_count].ip[INET_ADDRSTRLEN - 1] = '\0';
        ip_stats[ip_stats_count].total = 1;
        ip_stats[ip_stats_count].tcp = (protocol == IPPROTO_TCP) ? 1 : 0;
        ip_stats[ip_stats_count].udp = (protocol == IPPROTO_UDP) ? 1 : 0;
        ip_stats[ip_stats_count].other = (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) ? 1 : 0;
        ip_stats_count++;
    }
}


int get_tcp_payload_offset(const unsigned char *packet, int size, int datalink_type) {
    int offset = 0;

    // --- Определение смещения IP ---
    switch (datalink_type) {
        case DLT_EN10MB: // Ethernet
            offset = 14;
            break;
        case DLT_NULL:   // Loopback
        case DLT_LOOP:
            offset = 4;
            break;
        case DLT_RAW:    // IP напрямую
            offset = 0;
            break;
        case DLT_LINUX_SLL: // Linux cooked
            offset = 16;
            break;
        default:
            return -1; // Unsupported DLT
    }

    if (size < offset + 1) return -1;

    // --- IPv4 ---
    uint8_t version = (packet[offset] >> 4);
    if (version == 4) {
        if (size < offset + sizeof(struct iphdr)) return -1;
        const struct iphdr *iph = (const struct ip *)(packet + offset);
        if (iph->protocol != IPPROTO_TCP) return -1;

        int ip_header_len = iph->ihl * 4;
        if (size < offset + ip_header_len + sizeof(struct tcphdr)) return -1;

        const struct tcphdr *tcph = (const struct tcphdr *)(packet + offset + ip_header_len);
        int tcp_header_len = tcph->th_off * 4;

        return offset + ip_header_len + tcp_header_len;
    }
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

