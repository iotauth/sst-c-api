#include "wifi_rssi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int valid_iface(const char* iface) {
    /* iface goes into a command line: interface names only. */
    return iface && *iface && strlen(iface) < IFNAMSIZ &&
           strspn(iface, "abcdefghijklmnopqrstuvwxyz0123456789_-") ==
               strlen(iface);
}

int wifi_station_parse(const char* dump, wifi_station_info* out) {
    int stations = 0, have_signal = 0, have_rx = 0, signal = 0;
    unsigned long long rx = 0;
    for (const char* line = dump; line && *line;) {
        if (!strncmp(line, "Station ", 8)) ++stations;
        /* "\tsignal:  \t-17 [-17] dBm"; not "signal avg:". */
        if (!strncmp(line, "\tsignal:", 8))
            have_signal = sscanf(line + 8, " %d", &signal) == 1;
        if (!strncmp(line, "\trx packets:", 12))
            have_rx = sscanf(line + 12, " %llu", &rx) == 1;
        line = strchr(line, '\n');
        if (line) ++line;
    }
    if (stations != 1 || !have_signal || !have_rx || signal < -127 ||
        signal > 20)
        return -1;
    out->signal_dbm = (int8_t)signal;
    out->rx_packets = rx;
    return 0;
}

int wifi_station_read(const char* iface, wifi_station_info* out) {
    if (!valid_iface(iface)) return -1;
    char cmd[64], dump[16384];
    snprintf(cmd, sizeof(cmd), "/usr/sbin/iw dev %s station dump", iface);
    FILE* f = popen(cmd, "r");
    if (!f) {
        perror("Wi-Fi RSSI: iw");
        return -1;
    }
    size_t n = fread(dump, 1, sizeof(dump) - 1, f);
    int full = n == sizeof(dump) - 1;
    dump[n] = 0;
    if (pclose(f) != 0 || full || wifi_station_parse(dump, out)) {
        fprintf(stderr,
                "ERROR: Wi-Fi RSSI: no single peer with a signal on %s.\n",
                iface);
        return -1;
    }
    return 0;
}

int wifi_rssi_read(const char* iface, int8_t* rssi) {
    wifi_station_info info;
    if (wifi_station_read(iface, &info)) return -1;
    *rssi = info.signal_dbm;
    return 0;
}

int wifi_probe_peer(const char* iface, const char* peer_ip) {
    struct in_addr a;
    if (!valid_iface(iface) || !peer_ip || inet_pton(AF_INET, peer_ip, &a) != 1)
        return -1;
    /* No shell: ping's output is not needed, only that it ran. */
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int null = open("/dev/null", O_WRONLY);
        if (null >= 0) {
            dup2(null, STDOUT_FILENO);
            dup2(null, STDERR_FILENO);
        }
        execl("/usr/bin/ping", "ping", "-n", "-q", "-c", "1", "-W", "1", "-I",
              iface, peer_ip, (char*)NULL);
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR) return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

int wifi_fresh_begin(wifi_fresh_sampler* s) {
    wifi_station_info info;
    if (!s || !s->read || !s->probe || s->read(s->ctx, &info)) return -1;
    s->last_rx_packets = info.rx_packets;
    return 0;
}

int wifi_fresh_sample(wifi_fresh_sampler* s, int8_t* rssi) {
    for (int i = 0; i < WIFI_FRESH_TRIES; ++i) {
        wifi_station_info seen, now;
        s->probe(s->ctx);
        if (s->read(s->ctx, &seen)) return -1;
        if (seen.rx_packets <= s->last_rx_packets) continue;
        /* A new frame was counted. Its RSSI was recorded along with the
         * count, so this second read returns that frame's or a newer one's. */
        if (s->read(s->ctx, &now) || now.rx_packets < seen.rx_packets)
            return -1;
        *rssi = now.signal_dbm;
        s->last_rx_packets = now.rx_packets;
        return 0;
    }
    fprintf(stderr, "ERROR: Wi-Fi RSSI: no new frame from the peer.\n");
    return -1;
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

int wifi_rssi_socket_peer(int sock, char* ip, size_t capacity) {
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    if (getpeername(sock, (struct sockaddr*)&peer, &len) ||
        peer.sin_family != AF_INET ||
        !inet_ntop(AF_INET, &peer.sin_addr, ip, (socklen_t)capacity))
        return -1;
    return 0;
}
