#ifndef PRINT_H
#define PRINT_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <time.h>

void print_packet(const unsigned char *packet, int size, int datalink_type);
void print_dns(const unsigned char *dns_data, int dns_size);

#endif