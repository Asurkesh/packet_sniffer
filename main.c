#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

jmp_buf jump_buffer;
pcap_t *handle = NULL;

// Флаг для завершения pcap_loop через pcap_breakloop
void handle_sigint(int sig) {
    if (handle != NULL) {
        pcap_breakloop(handle);
    }
    printf("\nВозврат в главное меню...\n");
    longjmp(jump_buffer, 1);
}

// Обработка каждого пакета
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Пойман пакет длиной %d байт\n", header->len);
}

// Получение интерфейса по умолчанию
char* get_default_device() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Не удалось найти интерфейс по умолчанию: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    return dev;
}

// Захват пакетов с фильтром (или без)
void start_sniffing(const char *filter_exp) {
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    char *dev = get_default_device();

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Не удалось получить информацию о сети: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Не удалось открыть интерфейс %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    if (filter_exp && strlen(filter_exp) > 0) {
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Ошибка компиляции фильтра: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Ошибка установки фильтра: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    printf("Начинаем захват пакетов...\nНажмите Ctrl+C для возврата в меню.\n\n");

    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    handle = NULL;
}

// Главное меню
void show_main_menu() {
    while (1) {
        printf("\n==== МЕНЮ ====\n");
        printf("1. Слушать все пакеты\n");
        printf("2. Фильтрация по протоколу и порту\n");
        printf("3. Выход\n");
        printf("Ваш выбор: ");

        int choice;
        scanf("%d", &choice);
        getchar(); // захватываем \n

        if (choice == 1) {
            if (setjmp(jump_buffer) == 0) {
                start_sniffing(""); // без фильтра
            }
        } else if (choice == 2) {
            char protocol[10];
            int port;
            printf("Выберите протокол (tcp/udp/icmp): ");
            scanf("%9s", protocol);

            if (strcmp(protocol, "icmp") != 0) {
                printf("Введите порт (0 — все порты): ");
                scanf("%d", &port);
            } else {
                port = 0; // у ICMP нет портов
            }

            char filter[100] = {0};
            if (strcmp(protocol, "icmp") == 0) {
                snprintf(filter, sizeof(filter), "icmp");
            } else if (port > 0) {
                snprintf(filter, sizeof(filter), "%s port %d", protocol, port);
            } else {
                snprintf(filter, sizeof(filter), "%s", protocol);
            }

            if (setjmp(jump_buffer) == 0) {
                start_sniffing(filter);
            }
        } else if (choice == 3) {
            printf("Выход из программы...\n");
            exit(EXIT_SUCCESS);
        } else {
            printf("Неверный выбор.\n");
        }
    }
}

int main() {
    signal(SIGINT, handle_sigint);
    show_main_menu();
    return 0;
}
