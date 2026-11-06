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
#include <format>
#include <iostream>
#include <random>
#include <source_location>
#include <span>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "../../../src/c_api.h"
}

// Include the implementations to exercise their private byte/CSV helpers.
#include "../lib/metrics.cpp"

static void check(bool condition, std::source_location location =
                                      std::source_location::current()) {
    if (condition) return;
    std::cerr << std::format("{}:{}: check failed in {}\n",
                             location.file_name(), location.line(),
                             location.function_name());
    std::abort();
}

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
    check(domain == AF_INET && type == SOCK_RAW);
    check(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP);
    return capture().failure == PacketFailure::socket ? -1 : 42;
}

static int fake_setsockopt(int sock, int level, int option, const int* value,
                           socklen_t length) {
    check(sock == 42 && level == IPPROTO_IP && option == IP_HDRINCL);
    check(length == sizeof(*value) && *value == 1);
    return capture().failure == PacketFailure::option ? -1 : 0;
}

static ssize_t fake_sendto(int sock, const unsigned char* bytes, size_t length,
                           int flags, const sockaddr* destination,
                           socklen_t address_length) {
    check(sock == 42 && flags == 0 && length >= sizeof(ip));
    check(address_length == sizeof(sockaddr_in));
    auto address = std::bit_cast<sockaddr_in>(*destination);
    check(address.sin_family == AF_INET && ntohs(address.sin_port) == 21902);
    if (capture().failure == PacketFailure::send) return -1;
    capture().bytes.assign(bytes, bytes + length);
    return static_cast<ssize_t>(length);
}

static int fake_close(int sock) {
    check(sock == 42);
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
    check(sent && capture().closes == 1);
    auto bytes = std::span(capture().bytes);
    size_t transport_length =
        protocol == IPPROTO_TCP ? sizeof(tcphdr) : sizeof(udphdr);
    check(bytes.size() == sizeof(ip) + transport_length);
    check(csum16(bytes.first(sizeof(ip))) == 0);
    ip ipv4{};
    std::memcpy(&ipv4, bytes.data(), sizeof(ipv4));
    check(ipv4.ip_v == 4 && ipv4.ip_hl == 5 && ipv4.ip_p == protocol);
    check(ipv4.ip_src.s_addr == inet_addr("127.0.0.2"));
    check(ipv4.ip_dst.s_addr == inet_addr("127.0.0.1"));
    auto transport = bytes.subspan(sizeof(ip));
    auto source_port =
        (static_cast<unsigned>(transport[0]) << 8) | transport[1];
    check(source_port >= 40000 && source_port < 60000);
    check(((static_cast<unsigned>(transport[2]) << 8) | transport[3]) == 21902);
    if (protocol == IPPROTO_TCP) check(transport[13] == TH_SYN);
    // Verify the checksum over the IPv4 pseudo-header and full transport
    // header.
    std::vector<unsigned char> checksum(12 + transport.size());
    std::memcpy(checksum.data(), bytes.data() + 12, 8);
    checksum[9] = static_cast<unsigned char>(protocol);
    checksum[11] = static_cast<unsigned char>(transport.size());
    std::memcpy(checksum.data() + 12, transport.data(), transport.size());
    check(csum16(checksum) == 0);
}

static void check_packet_failures() {
    using enum PacketFailure;
    for (auto failure : {socket, option, send}) {
        for (auto send_packet :
             {send_raw_syn_packets_measured, send_raw_udp_packets_measured}) {
            capture() = {};
            capture().failure = failure;
            MetricsRow row;
            check(!send_packet("127.0.0.2", "127.0.0.1", 21902, 1, &row));
            check(capture().closes == (failure == socket ? 0 : 1));
            check(row.successes == 0);
            check(row.failures == (failure == send ? 1 : 0));
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

static void check_metrics(const std::filesystem::path& build_directory) {
    auto pattern = build_directory / "sst-metrics-XXXXXX";
    std::vector<char> buffer(pattern.native().begin(), pattern.native().end());
    buffer.push_back('\0');
    check(mkdtemp(buffer.data()) != nullptr);
    std::filesystem::path directory(buffer.data());
    using enum std::filesystem::perms;
    check((std::filesystem::status(directory).permissions() &
           (group_all | others_all)) == none);
    auto base = directory / "metrics.csv";
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
    testbed_metrics::metrics_file().stream.close();
    std::ifstream input(directory / "metrics1.csv");
    std::string line;
    check(static_cast<bool>(std::getline(input, line)));
    check(csv_fields(line).size() == 12);
    check(static_cast<bool>(std::getline(input, line)));
    auto fields = csv_fields(line);
    check(fields.size() == 12 && fields[0] == "empty");
    check(fields[4] == "0" && fields[5] == "0" && fields[6] == "0");
    check(fields[7] == "0" && fields[8] == "0");
    check(static_cast<bool>(std::getline(input, line)));
    fields = csv_fields(line);
    check(fields.size() == 12 && fields[0] == "samples" && fields[1] == "2");
    check(fields[4] == "1" && fields[5] == "1" && fields[6] == "20");
    check(fields[7] == "10" && fields[8] == "30");
    check(fields[10].size() - fields[10].find('.') == 4);
    check(fields[11].size() - fields[11].find('.') == 4);
    check(!std::getline(input, line));
    std::ifstream original(base);
    check(static_cast<bool>(std::getline(original, line)) &&
          line == "preserve this file");
    std::filesystem::remove_all(directory);
}

static void check_scenario_parsing() {
    auto basic = parse_step("12,hello");
    check(basic.sleep_ms == 12 && basic.message == "hello");
    check(basic.type == AttackType::NONE && basic.parameter.empty());
    auto replay = parse_step("0,message,REPLAY,seq=7");
    check(replay.type == AttackType::REPLAY && replay.target.empty());
    SST_session_ctx_t session{};
    run_replay(replay.parameter, &session);
    check(session.sent_seq_num == 7);
    auto udp = parse_step("0,message,dosu,1,auth");
    check(udp.type == AttackType::DOSU && udp.parameter == "1" &&
          udp.target == "auth");
    check(parseAttackTarget("Server") == AttackTarget::TARGET_SERVER);
    std::array<std::string, 5> values{"client", "config", "scenario",
                                      "-metrics", "127.0.0.2"};
    std::array<char*, 5> args{};
    for (size_t i = 0; i < values.size(); ++i) args[i] = values[i].data();
    ClientOptions options;
    check(parse_options(args.size(), args.data(), options));
    check(options.metrics && std::string(options.src_ip) == values.back());
    std::swap(args[3], args[4]);
    check(!parse_options(args.size(), args.data(), options));
}

int main(int argc, char* argv[]) {
    check(argc == 2);
    const std::array<unsigned char, 8> reference{0,    1,    0xf2, 3,
                                                 0xf4, 0xf5, 0xf6, 0xf7};
    check(ntohs(csum16(reference)) == 0x220d);
    check_packet(IPPROTO_TCP);
    check_packet(IPPROTO_UDP);
    check_packet_failures();
    check_metrics(argv[1]);
    check_scenario_parsing();
    std::puts("Testbed packet and metrics regressions passed.");
}
