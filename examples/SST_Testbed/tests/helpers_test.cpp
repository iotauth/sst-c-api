#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <random>
#include <span>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "../../../src/c_api.h"
}

// Include the implementations to exercise their private byte/CSV helpers.
#include "../lib/metrics.cpp"

#define CHECK(condition)                                            \
    do {                                                            \
        if (!(condition)) {                                         \
            std::fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, \
                         #condition);                               \
            std::abort();                                           \
        }                                                           \
    } while (false)

enum class PacketFailure { none, socket, option, send };

struct PacketCapture {
    PacketFailure failure = PacketFailure::none;
    std::vector<unsigned char> bytes;
    int closes = 0;
};

static PacketCapture& capture() {
    static PacketCapture result;
    return result;
}

static int fake_socket(int domain, int type, int protocol) {
    CHECK(domain == AF_INET && type == SOCK_RAW);
    CHECK(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
    return capture().failure == PacketFailure::socket ? -1 : 42;
}

static int fake_setsockopt(int sock, int level, int option, const int* value,
                           socklen_t length) {
    CHECK(sock == 42 && level == IPPROTO_IP && option == IP_HDRINCL);
    CHECK(length == sizeof(*value) && *value == 1);
    return capture().failure == PacketFailure::option ? -1 : 0;
}

static ssize_t fake_sendto(int sock, const unsigned char* bytes, size_t length,
                           int flags, const sockaddr* destination,
                           socklen_t address_length) {
    CHECK(sock == 42 && flags == 0 && length >= sizeof(ip));
    CHECK(address_length == sizeof(sockaddr_in));
    auto address = std::bit_cast<sockaddr_in>(*destination);
    CHECK(address.sin_family == AF_INET && ntohs(address.sin_port) == 21902);
    if (capture().failure == PacketFailure::send) return -1;
    capture().bytes.assign(bytes, bytes + length);
    return static_cast<ssize_t>(length);
}

static int fake_close(int sock) {
    CHECK(sock == 42);
    ++capture().closes;
    return 0;
}

#define socket fake_socket
#define setsockopt fake_setsockopt
#define sendto fake_sendto
#define close fake_close
#include "../lib/send_syn.cpp"
#undef socket
#undef setsockopt
#undef sendto
#undef close

#define main testbed_client_main
#include "../client.cpp"
#undef main

static void check_packet(int protocol) {
    capture() = {};
    bool sent = protocol == IPPROTO_TCP
                    ? send_raw_syn_packets("127.0.0.2", "127.0.0.1", 21902, 1)
                    : send_raw_udp_packets("127.0.0.2", "127.0.0.1", 21902, 1);
    CHECK(sent && capture().closes == 1);
    auto bytes = std::span(capture().bytes);
    size_t transport_length =
        protocol == IPPROTO_TCP ? sizeof(tcphdr) : sizeof(udphdr);
    CHECK(bytes.size() == sizeof(ip) + transport_length);
    CHECK(csum16(bytes.first(sizeof(ip))) == 0);
    ip ipv4{};
    std::memcpy(&ipv4, bytes.data(), sizeof(ipv4));
    CHECK(ipv4.ip_v == 4 && ipv4.ip_hl == 5 && ipv4.ip_p == protocol);
    CHECK(ipv4.ip_src.s_addr == inet_addr("127.0.0.2"));
    CHECK(ipv4.ip_dst.s_addr == inet_addr("127.0.0.1"));
    auto transport = bytes.subspan(sizeof(ip));
    auto source_port =
        (static_cast<unsigned>(transport[0]) << 8) | transport[1];
    CHECK(source_port >= 40000 && source_port < 60000);
    CHECK(((static_cast<unsigned>(transport[2]) << 8) | transport[3]) == 21902);
    if (protocol == IPPROTO_TCP) CHECK(transport[13] == TH_SYN);
    // Verify the checksum over the IPv4 pseudo-header and full transport
    // header.
    std::vector<unsigned char> checksum(12 + transport.size());
    std::memcpy(checksum.data(), bytes.data() + 12, 8);
    checksum[9] = static_cast<unsigned char>(protocol);
    checksum[11] = static_cast<unsigned char>(transport.size());
    std::memcpy(checksum.data() + 12, transport.data(), transport.size());
    CHECK(csum16(checksum) == 0);
}

static void check_packet_failures() {
    for (auto failure :
         {PacketFailure::socket, PacketFailure::option, PacketFailure::send}) {
        for (auto send_packet :
             {send_raw_syn_packets_measured, send_raw_udp_packets_measured}) {
            capture() = {};
            capture().failure = failure;
            MetricsRow row;
            CHECK(!send_packet("127.0.0.2", "127.0.0.1", 21902, 1, &row));
            CHECK(capture().closes ==
                  (failure == PacketFailure::socket ? 0 : 1));
            CHECK(row.successes == 0);
            CHECK(row.failures == (failure == PacketFailure::send ? 1 : 0));
        }
    }
}

static std::vector<std::string> csv_fields(const std::string& line) {
    std::istringstream input(line);
    std::vector<std::string> fields;
    std::string field;
    while (std::getline(input, field, ',')) fields.push_back(field);
    return fields;
}

static void check_metrics() {
    std::string pattern =
        std::format("{}/sst-metrics-XXXXXX",
                    std::filesystem::temp_directory_path().string());
    CHECK(mkdtemp(pattern.data()) != nullptr);
    auto base = std::filesystem::path(pattern) / "metrics.csv";
    {
        std::ofstream existing(base);
        existing << "preserve this file\n";
    }
    metrics_open_new_file(base.string());
    metrics_write_header_if_empty();
    metrics_write_header_if_empty();
    auto empty = metrics_begin_row("empty");
    metrics_end_row_and_write(empty);
    auto samples = metrics_begin_row("samples");
    samples.malicious_number = "2";
    metrics_add_sample(samples, 10, true);
    metrics_add_sample(samples, 30, false);
    metrics_end_row_and_write(samples);
    metrics_file().stream.close();
    std::ifstream input(std::filesystem::path(pattern) / "metrics1.csv");
    std::string line;
    CHECK(static_cast<bool>(std::getline(input, line)));
    CHECK(csv_fields(line).size() == 12);
    CHECK(static_cast<bool>(std::getline(input, line)));
    auto fields = csv_fields(line);
    CHECK(fields.size() == 12 && fields[0] == "empty");
    CHECK(fields[4] == "0" && fields[5] == "0" && fields[6] == "0");
    CHECK(fields[7] == "0" && fields[8] == "0");
    CHECK(static_cast<bool>(std::getline(input, line)));
    fields = csv_fields(line);
    CHECK(fields.size() == 12 && fields[0] == "samples" && fields[1] == "2");
    CHECK(fields[4] == "1" && fields[5] == "1" && fields[6] == "20");
    CHECK(fields[7] == "10" && fields[8] == "30");
    CHECK(fields[10].size() - fields[10].find('.') == 4);
    CHECK(fields[11].size() - fields[11].find('.') == 4);
    CHECK(!std::getline(input, line));
    std::ifstream original(base);
    CHECK(static_cast<bool>(std::getline(original, line)) &&
          line == "preserve this file");
    std::filesystem::remove_all(pattern);
}

static void check_scenario_parsing() {
    auto basic = parse_step("12,hello");
    CHECK(basic.sleep_ms == 12 && basic.message == "hello");
    CHECK(basic.type == AttackType::NONE && basic.parameter.empty());
    auto replay = parse_step("0,message,REPLAY,seq=7");
    CHECK(replay.type == AttackType::REPLAY && replay.target.empty());
    SST_session_ctx_t session{};
    run_replay(replay.parameter, &session);
    CHECK(session.sent_seq_num == 7);
    auto udp = parse_step("0,message,dosu,1,auth");
    CHECK(udp.type == AttackType::DOSU && udp.parameter == "1" &&
          udp.target == "auth");
    CHECK(parseAttackTarget("Server") == AttackTarget::TARGET_SERVER);
    std::array<std::string, 5> values{"client", "config", "scenario",
                                      "-metrics", "127.0.0.2"};
    std::array<char*, 5> args{};
    for (size_t i = 0; i < values.size(); ++i) args[i] = values[i].data();
    ClientOptions options;
    CHECK(parse_options(args.size(), args.data(), options));
    CHECK(options.metrics && std::string(options.src_ip) == values.back());
    std::swap(args[3], args[4]);
    CHECK(!parse_options(args.size(), args.data(), options));
}

int main() {
    const std::array<unsigned char, 8> reference{0,    1,    0xf2, 3,
                                                 0xf4, 0xf5, 0xf6, 0xf7};
    CHECK(ntohs(csum16(reference)) == 0x220d);
    check_packet(IPPROTO_TCP);
    check_packet(IPPROTO_UDP);
    check_packet_failures();
    check_metrics();
    check_scenario_parsing();
    std::puts("Testbed packet and metrics regressions passed.");
}
