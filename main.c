#include <pcap.h>
#include <stdio.h>

void packet_handler(char *args, const struct pcap_pkthdr *header, const char *packet) {
    printf("Пойман пакет длиной %d байт\n", header->len);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Ошибка: %s\n", errbuf);
        return 1;
    }

    device = alldevs;  // выбираем первое устройство

    pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Ошибка открытия: %s\n", errbuf);
        return 2;
    }

    pcap_loop(handle, 5, packet_handler, NULL);
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}