#include "sockets.hpp"

#include <arpa/inet.h>

#include <iostream>
#include <utility>

#include "log/log_manager.hpp"

namespace sst {
namespace {

// Keep ownership local until address creation and socket setup both succeed.
std::unique_ptr<SST_SocketInfo> open_socket(SST_SOCK_DOMAIN domain,
                                            const char* host, int port) {
    auto info = std::make_unique<SST_SocketInfo>();
    if (domain == SST_SOCK_INET) {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            std::cerr << "Invalid IPv4 address: " << host << std::endl;
            return nullptr;
        }
        info->len = sizeof(addr);
        info->addr = SST_SocketInfo::AllocAddr(&addr, info->len);
    } else if (domain == SST_SOCK_INET6) {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (inet_pton(AF_INET6, host, &addr.sin6_addr) != 1) {
            std::cerr << "Invalid IPv6 address: " << host << std::endl;
            return nullptr;
        }
        info->len = sizeof(addr);
        info->addr = SST_SocketInfo::AllocAddr(&addr, info->len);
    } else {
        std::cerr << "Unsupported socket domain" << std::endl;
        return nullptr;
    }
    if (!info->addr) {
        std::cerr << "Failed to allocate socket address" << std::endl;
        return nullptr;
    }
    info->sock = ::socket(domain, SOCK_STREAM, 0);
    if (info->sock == -1) {
        std::cerr << "Failed to create socket" << std::endl;
        return nullptr;
    }
    return info;
}

}  // namespace

Socket::~Socket() { Close(); }

void Socket::Close() {
    std::lock_guard<std::mutex> lock(gate);
    if (info) {
        LOG_TRA << "Closing socket with FD: " << info->sock;
        info.reset();
    }
}

int Socket::Read(char* buf, int nbytes) const {
    if (!info || info->sock == -1) return -1;
    int total = 0;
    while (total < nbytes) {
        int n = ::read(info->sock, buf + total, nbytes - total);
        if (n <= 0) return (n == 0 && total > 0) ? total : n;
        total += n;
    }
    return total;
}

int Socket::Write(char* buf, int nbytes) {
    std::lock_guard<std::mutex> lock(gate);
    if (!info || info->sock == -1) {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    return ::write(info->sock, buf, nbytes);
}

void Socket::SetSocketInfo(std::unique_ptr<SST_SocketInfo> socket_info) {
    std::lock_guard<std::mutex> lock(gate);
    info = std::move(socket_info);
}

std::unique_ptr<SST_SocketInfo> Socket::GetSocketInfo() const {
    std::lock_guard<std::mutex> lock(gate);
    if (!info) return nullptr;

    // Duplicating the descriptor lets either owner close its handle without
    // invalidating the other. Both handles still refer to the same stream.
    auto copy = std::make_unique<SST_SocketInfo>();
    copy->sock = (info->sock != -1) ? ::dup(info->sock) : -1;
    if (info->sock != -1 && copy->sock == -1) {
        std::cerr << "Failed to dup socket fd in GetSocketInfo" << std::endl;
        return nullptr;
    }
    copy->len = info->len;
    if (info->addr) {
        copy->addr = SST_SocketInfo::AllocAddr(info->addr.get(), info->len);
        if (!copy->addr) {
            std::cerr << "Failed to allocate memory for GetSocketInfo"
                      << std::endl;
            return nullptr;
        }
    }
    return copy;
}

int Socket::get_fd() const { return info ? info->sock : -1; }

ClientSocket::ClientSocket(std::unique_ptr<SST_SocketInfo> socket_info) {
    SetSocketInfo(std::move(socket_info));
}

ClientSocket::ClientSocket(SST_SOCK_DOMAIN domain, const char* host, int port) {
    SetSocketInfo(open_socket(domain, host, port));
}

int ClientSocket::Connect() {
    const auto& info = get_info_ref();
    if (!info || info->sock == -1 || !info->addr) {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    return ::connect(info->sock, info->addr.get(), info->len);
}

ServerSocket::ServerSocket(SST_SOCK_DOMAIN domain, const char* host, int port) {
    auto info = open_socket(domain, host, port);
    if (!info) return;

    // Allow a restarted listener to bind while old connections are in
    // TIME_WAIT.
    int on = 1;
    if (::setsockopt(info->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) ==
        -1) {
        std::cerr << "Failed to set SO_REUSEADDR for ServerSocket" << std::endl;
        return;
    }
    if (::bind(info->sock, info->addr.get(), info->len) == -1) {
        std::cerr << "Failed to bind socket for ServerSocket" << std::endl;
        return;
    }
    if (::listen(info->sock, 5) == -1) {
        std::cerr << "Failed to listen on socket for ServerSocket" << std::endl;
        return;
    }
    SetSocketInfo(std::move(info));
}

int ServerSocket::Accept(ServerSocket& acceptedSocket) {
    if (get_fd() == -1) {
        std::cerr << "Invalid socket info for accepting connection"
                  << std::endl;
        return -1;
    }
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    auto peer = std::make_unique<SST_SocketInfo>();
    peer->sock = ::accept(get_fd(), reinterpret_cast<sockaddr*>(&addr), &len);
    if (peer->sock == -1) {
        std::cerr << "Failed to accept connection on ServerSocket" << std::endl;
        return -1;
    }
    peer->len = len;
    peer->addr = SST_SocketInfo::AllocAddr(&addr, len);
    if (!peer->addr) {
        // peer owns the accepted descriptor even if address allocation fails.
        std::cerr << "Failed to allocate memory for accepted peer address"
                  << std::endl;
        return -1;
    }
    acceptedSocket.SetSocketInfo(std::move(peer));
    return 0;
}

}  // namespace sst
