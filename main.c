#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <arpa/inet.h>

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


#define COLOR_RESET "\033[0m"
#define COLOR_PROTO "\033[1;34m"
#define COLOR_IP    "\033[1;32m"
#define COLOR_PORT  "\033[1;33m"
#define COLOR_SIZE  "\033[1;35m"
#define COLOR_MAC "\033[1;36m"

pcap_t *handle = NULL;

void signal_handler(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

void print_packet(const unsigned char *packet, int size) {
    int eth_header_len = 14;
    int ip_header_offset = 0;
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

    const struct ether_header *eth = (const struct ether_header *)packet;
    ether_type = ntohs(eth->ether_type);

    // Определяем, есть ли Ethernet-заголовок
    if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6 || ether_type == ETHERTYPE_ARP) {
        has_eth = 1;
        ip_header_offset = eth_header_len;

        // MAC-адреса
        char src_mac[18], dst_mac[18];
        snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                 eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        snprintf(dst_mac, sizeof(dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                 eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        printf(COLOR_MAC "MAC %s -> %s\n" COLOR_RESET, src_mac, dst_mac);
    } else {
        ip_header_offset = 0; // вероятно loopback
    }

    // Обработка ARP
    if (has_eth && ether_type == ETHERTYPE_ARP) {
        struct arphdr *arp_header = (struct arphdr *)(packet + eth_header_len);
        unsigned char *arp_ptr = (unsigned char *)(packet + eth_header_len + sizeof(struct arphdr));

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

    // Обработка IPv4
    const struct iphdr *iph = (const struct iphdr *)(packet + ip_header_offset);
    if ((has_eth && ether_type == ETHERTYPE_IP) || (!has_eth && iph->version == 4)) {
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->saddr), src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &(iph->daddr), dst_ip, sizeof(dst_ip));

        if (iph->protocol == IPPROTO_TCP) {
            const struct tcphdr *tcph = (const struct tcphdr *)(packet + ip_header_offset + iph->ihl * 4);
            printf(COLOR_PROTO "[TCP] " COLOR_RESET);
            printf(COLOR_IP "%s:%s%d" COLOR_RESET " -> " COLOR_IP "%s:%s%d" COLOR_RESET,
                   src_ip, COLOR_PORT, ntohs(tcph->source),
                   dst_ip, COLOR_PORT, ntohs(tcph->dest));
        } else if (iph->protocol == IPPROTO_UDP) {
            const struct udphdr *udph = (const struct udphdr *)(packet + ip_header_offset + iph->ihl * 4);
            printf(COLOR_PROTO "[UDP] " COLOR_RESET);
            printf(COLOR_IP "%s:%s%d" COLOR_RESET " -> " COLOR_IP "%s:%s%d" COLOR_RESET,
                   src_ip, COLOR_PORT, ntohs(udph->source),
                   dst_ip, COLOR_PORT, ntohs(udph->dest));
        } else {
            printf(COLOR_PROTO "[IPv4 протокол %d] " COLOR_RESET, iph->protocol);
            printf(COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, src_ip, dst_ip);
        }
    }
    // Обработка IPv6
    else if ((has_eth && ether_type == ETHERTYPE_IPV6) || (!has_eth && ((packet[ip_header_offset] >> 4) == 6))) {
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
    (void)args;
    print_packet(packet, header->len);
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
    printf("3. Выход\n");
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

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    handle = NULL;
}

int main() {
    while (1) {
        int choice = main_menu();
        if (choice == 3) {
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
        } else {
            printf("Неверный выбор\n");
        }

        free(iface);
    }
    return 0;
}

