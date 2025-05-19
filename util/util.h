#ifndef UTIL_H
#define UTIL_H

#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h> 

// Цвета для вывода в консоль
#define COLOR_RESET "\033[0m"
#define COLOR_PROTO "\033[1;34m"
#define COLOR_IP    "\033[1;32m"
#define COLOR_PORT  "\033[1;33m"
#define COLOR_SIZE  "\033[1;35m"
#define COLOR_MAC   "\033[1;36m"
#define COLOR_DNS   "\033[1;37m"
#define COLOR_HTTP  "\033[1;40m"
#define COLOR_ICMP  "\033[1;38m"

// Максимальное количество IP для статистики
#define MAX_IPS 2048

// Флаги TCP для удобства
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

// Структура для статистики
typedef struct {
    unsigned long total_packets;
    unsigned long tcp_count;
    unsigned long udp_count;
    unsigned long icmp_count;
    unsigned long igmp_count;
    unsigned long arp_count;
    unsigned long ipv6_count;
    unsigned long other_count;
} Stats;

// Структура для статистики по IP
typedef struct {
    char ip[INET_ADDRSTRLEN];
    unsigned long total_packets;
    unsigned long total_bytes;
    unsigned long tcp_count;
    unsigned long udp_count;
    unsigned long icmp_count;
    unsigned long igmp_count;
    unsigned long esp_count;
    unsigned long gre_count;
    unsigned long other_count;
} IpStat;

// Прототипы простых вспомогательных функций
int get_ip_header_offset(int datalink_type);
int compare_by_bytes_desc(const void *a, const void *b);
int get_tcp_payload_offset(const unsigned char *packet, int size, int datalink_type);

#endif