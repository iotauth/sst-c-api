#include "wifi_rssi.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int wifi_rssi_read(const char* iface, int8_t* rssi) {
    /* iface goes into a command line: interface names only. */
    if (!iface || !*iface || strlen(iface) >= IFNAMSIZ ||
        strspn(iface, "abcdefghijklmnopqrstuvwxyz0123456789_-") !=
            strlen(iface))
        return -1;
    char cmd[64], line[256];
    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s station dump", iface);
    FILE* f = popen(cmd, "r");
    if (!f) {
        perror("Wi-Fi RSSI: iw");
        return -1;
    }
    int stations = 0, found = 0, value = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "Station ", 8)) ++stations;
        /* "\tsignal:  \t-17 [-17] dBm"; not "signal avg:". */
        const char* s = strstr(line, "\tsignal:");
        if (s && sscanf(s + 8, " %d", &value) == 1) found = 1;
    }
    if (pclose(f) != 0 || stations != 1 || !found || value < -127 ||
        value > 20) {
        fprintf(stderr,
                "ERROR: Wi-Fi RSSI: no single peer with a signal on %s "
                "(stations=%d).\n",
                iface, stations);
        return -1;
    }
    *rssi = (int8_t)value;
    return 0;
}

int wifi_rssi_socket_iface(int sock, char* iface, size_t capacity) {
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr*)&local, &len) ||
        local.sin_family != AF_INET)
        return -1;
    struct ifaddrs* list;
    if (getifaddrs(&list)) return -1;
    int rc = -1;
    for (struct ifaddrs* a = list; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET) continue;
        const struct sockaddr_in* in = (const struct sockaddr_in*)a->ifa_addr;
        if (in->sin_addr.s_addr == local.sin_addr.s_addr &&
            strlen(a->ifa_name) < capacity) {
            strcpy(iface, a->ifa_name);
            rc = 0;
            break;
        }
    }
    freeifaddrs(list);
    return rc;
}
