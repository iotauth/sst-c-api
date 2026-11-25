/**
 * @file socket_test.cpp
 * @brief Socket ownership and loopback I/O tests; no Auth server required.
 */

#include <arpa/inet.h>
#include <fcntl.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "../src/net/sockets.hpp"

namespace {

// Keep checks and their side effects enabled in Release builds too.
void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "Socket test failed: %s\n", message);
        std::exit(1);
    }
}

void test_basic_socket_lifecycle() {
    sst::Socket socket;
    check(socket.get_fd() == -1, "default socket is closed");
    check(!socket.GetSocketInfo(), "uninitialized socket has no info");
    socket.Close();
    socket.Close();
    char byte = 0;
    check(socket.Read(&byte, 1) == -1, "closed socket rejects reads");
    check(socket.Write(&byte, 1) == -1, "closed socket rejects writes");
}

void test_invalid_addresses() {
    sst::ClientSocket ipv4(sst::SST_SOCK_INET, "invalid", 8080);
    sst::ClientSocket ipv6(sst::SST_SOCK_INET6, "127.0.0.1", 8080);
    sst::ServerSocket server(sst::SST_SOCK_INET, "invalid", 0);
    check(ipv4.get_fd() == -1 && ipv6.get_fd() == -1,
          "invalid client addresses leave no open descriptor");
    check(server.get_fd() == -1, "invalid listener address fails");
    check(ipv4.Connect() == -1, "invalid client cannot connect");
    check(server.Accept(server) == -1, "invalid listener cannot accept");
}

int listener_port(int fd, sst::SST_SOCK_DOMAIN domain) {
    sockaddr_storage storage{};
    auto address = sst::SST_SocketInfo::AllocAddr(&storage, sizeof(storage));
    check(address != nullptr, "allocate listener address");
    socklen_t length = sizeof(storage);
    check(::getsockname(fd, address.get(), &length) == 0,
          "query listener address");
    if (domain == sst::SST_SOCK_INET) {
        sockaddr_in ipv4{};
        check(length == sizeof(ipv4), "IPv4 address length");
        std::memcpy(&ipv4, address.get(), sizeof(ipv4));
        return ntohs(ipv4.sin_port);
    }
    sockaddr_in6 ipv6{};
    check(length == sizeof(ipv6), "IPv6 address length");
    std::memcpy(&ipv6, address.get(), sizeof(ipv6));
    return ntohs(ipv6.sin6_port);
}

void test_loopback(sst::SST_SOCK_DOMAIN domain, const char* host) {
    // Ephemeral ports let tests run alongside other SST instances.
    sst::ServerSocket server(domain, host, 0);
    check(server.get_fd() != -1, "create listener");
    sst::ClientSocket client(domain, host,
                             listener_port(server.get_fd(), domain));
    check(client.get_fd() != -1, "create client");
    check(client.Connect() == 0, "connect to listener");

    sst::ServerSocket accepted(domain, host, 0);
    int replaced_fd = accepted.get_fd();
    check(replaced_fd != -1, "create accept destination");
    check(server.Accept(accepted) == 0, "accept client");
    check(::fcntl(replaced_fd, F_GETFD) == -1 && errno == EBADF,
          "accept closes the replaced descriptor");

    auto copy = client.GetSocketInfo();
    check(copy && copy->sock != -1 && copy->sock != client.get_fd(),
          "copy owns a distinct descriptor");
    check(copy->addr && copy->addr->sa_family == domain,
          "copy retains the address family");
    int original_fd = client.get_fd();
    client.Close();
    check(::fcntl(original_fd, F_GETFD) == -1 && errno == EBADF,
          "close releases original descriptor");

    // The duplicate must remain usable after the original owner closes.
    int duplicate_fd = copy->sock;
    {
        sst::ClientSocket duplicate(std::move(copy));
        std::array<char, 4> message{'S', 'S', 'T', '\0'};
        check(duplicate.Write(message.data(), message.size()) == message.size(),
              "write through duplicate");
        check(::shutdown(duplicate.get_fd(), SHUT_WR) == 0,
              "close the sending direction");
        std::array<char, 16> received{};
        check(accepted.Read(received.data(), received.size()) == message.size(),
              "read returns partial data at EOF");
        check(std::memcmp(received.data(), message.data(), message.size()) == 0,
              "received bytes match");
        check(accepted.Read(received.data(), received.size()) == 0,
              "subsequent read reports EOF");
    }
    check(::fcntl(duplicate_fd, F_GETFD) == -1 && errno == EBADF,
          "destruction closes the duplicated descriptor");

    int accepted_fd = accepted.get_fd();
    server.Close();
    check(server.Accept(accepted) == -1 && accepted.get_fd() == accepted_fd,
          "failed accept preserves its destination");
}

}  // namespace

int main() {
    test_basic_socket_lifecycle();
    test_invalid_addresses();
    test_loopback(sst::SST_SOCK_INET, "127.0.0.1");
    test_loopback(sst::SST_SOCK_INET6, "::1");
    std::printf("All Socket API tests passed.\n");
    return 0;
}
