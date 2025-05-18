#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

#define COLOR_RESET "\033[0m"
#define COLOR_PROTO "\033[1;34m"
#define COLOR_IP    "\033[1;32m"
#define COLOR_PORT  "\033[1;33m"
#define COLOR_SIZE  "\033[1;35m"

pcap_t *handle = NULL;

void signal_handler(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
}

void print_packet(const u_char *packet, int size) {
    struct ip *iph = (struct ip*)(packet + 14); // Ethernet header 14 байт
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(packet + 14 + iph->ip_hl * 4);
        printf(COLOR_PROTO "[TCP] " COLOR_RESET);
        printf(COLOR_IP "%s:%s%d" COLOR_RESET, src_ip, COLOR_PORT, ntohs(tcph->source));
        printf(" -> ");
        printf(COLOR_IP "%s:%s%d" COLOR_RESET, dst_ip, COLOR_PORT, ntohs(tcph->dest));
    } else if (iph->ip_p == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)(packet + 14 + iph->ip_hl * 4);
        printf(COLOR_PROTO "[UDP] " COLOR_RESET);
        printf(COLOR_IP "%s:%s%d" COLOR_RESET, src_ip, COLOR_PORT, ntohs(udph->source));
        printf(" -> ");
        printf(COLOR_IP "%s:%s%d" COLOR_RESET, dst_ip, COLOR_PORT, ntohs(udph->dest));
    } else {
        printf(COLOR_PROTO "[OTHER %d] " COLOR_RESET, iph->ip_p);
        printf(COLOR_IP "%s" COLOR_RESET " -> " COLOR_IP "%s" COLOR_RESET, src_ip, dst_ip);
    }

    printf(" " COLOR_SIZE "[%d bytes]" COLOR_RESET "\n", size);
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
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

    handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
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
        char *iface = select_interface();

        int choice = main_menu();
        if (choice == 3) {
            free(iface);
            printf("Выход...\n");
            break;
        }

        if (choice == 1) {
            start_sniffer(iface, "ip");
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
