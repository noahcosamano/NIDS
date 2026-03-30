#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>
#include <stdio.h>
#include <winsock2.h> // Required for inet_ntoa

#pragma comment(lib, "ws2_32.lib") // Link Windows Socket library

void GetDevices() {
    pcap_if_t* alldevs;
    pcap_if_t* d;
    pcap_addr_t* a;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    }

    for (d = alldevs; d; d = d->next) {
        printf("Device: %s\n", d->name);
        if (d->description) printf("  Description: %s\n", d->description);

        // Loop through all addresses assigned to this interface
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) { // Look for IPv4
                printf("  IPv4 Address: %s\n",
                    inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr));
            }
        }
        printf("\n");
    }

    pcap_freealldevs(alldevs);
}