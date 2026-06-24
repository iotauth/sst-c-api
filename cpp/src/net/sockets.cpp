#include "sockets.hpp"
#include "log/log_manager.hpp"

// Implementation of Socket class methods
sst::Socket::Socket() : info(nullptr) {}

sst::Socket::~Socket()
{
    Close();
}

void sst::Socket::Close()
{
    std::lock_guard<std::mutex> lock(gate);
    if (info)
    {
        LOG_TRA << "Closing socket with FD: " << info->sock;
        info.reset();
    }
}

int sst::Socket::Pending() const
{
    if (!info || info->sock == -1)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    int pending;
    if (ioctl(info->sock, FIONREAD, &pending) == -1)
    {
        std::cerr << "Failed to get pending bytes" << std::endl;
        return -1;
    }
    return pending;
}

bool sst::Socket::ReadyToReadTimeOut(int timeout) const
{
    if (!info)
        return false;
    struct pollfd fds[1];
    fds[0].fd = info->sock;
    fds[0].events = POLLIN;
    return poll(fds, 1, timeout) > 0 && (fds[0].revents & POLLIN); // Use poll for timeout [1]
}

bool sst::Socket::ReadyToRead() const
{
    if (!info)
    {
        return false;
    }
    struct pollfd fds[1];
    fds[0].fd = info->sock;
    fds[0].events = POLLIN;
    int ret = poll(fds, 1, -1);
    if (ret > 0 && (fds[0].revents & POLLIN))
    {
        return true;
    }
    std::cerr << "Socket with FD: " << info->sock << " is not ready to read." << std::endl;
    return false;
}

int sst::Socket::Read(char *buf, int nbytes) const
{
    if (!info || info->sock == -1)
        return -1;
    int total = 0;
    while (total < nbytes)
    {
        int n = read(info->sock, buf + total, nbytes - total);
        if (n <= 0)
            return (n == 0 && total > 0) ? total : n; // EOF or error
        total += n;
    }
    return total;
}

int sst::Socket::Write(char *buf, int nbytes)
{
    std::lock_guard<std::mutex> lock(gate);
    if (!info || info->sock == -1)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    return write(info->sock, buf, nbytes); // Standard write [1]
}

int sst::Socket::NonBlockingRead(char *buf, int size, int timeout) const
{
    if (!info)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    int flags = fcntl(info->sock, F_GETFL, 0);
    fcntl(info->sock, F_SETFL, flags | O_NONBLOCK);

    int ret = read(info->sock, buf, size);
    if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        if (ReadyToReadTimeOut(timeout))
        {
            ret = read(info->sock, buf, size);
        }
        else
        {
            LOG_TRA << "Socket with FD: " << info->sock << " read timed out";
            ret = 0; // Indicate timeout
        }
    }
    fcntl(info->sock, F_SETFL, flags); // Restore socket flags
    return ret;
}

int sst::Socket::NonBlockingWrite(char *buf, int size, int timeout)
{
    std::lock_guard<std::mutex> lock(gate);
    if (!info)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    int flags = fcntl(info->sock, F_GETFL, 0);
    fcntl(info->sock, F_SETFL, flags | O_NONBLOCK);

    int ret = write(info->sock, buf, size);
    if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
    {
        struct pollfd fds[1];
        fds[0].fd = info->sock;
        fds[0].events = POLLOUT;
        if (poll(fds, 1, timeout) > 0)
        {
            ret = write(info->sock, buf, size);
        }
        else
        {
            LOG_TRA << "Socket with FD: " << info->sock << " write timed out";
            ret = 0; // Indicate timeout
        }
    }
    fcntl(info->sock, F_SETFL, flags);
    return ret;
}

void sst::Socket::DebugDump() const
{
    if (!info || info->sock == -1)
    {
        return;
    }

    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);

    if (getsockname(info->sock, reinterpret_cast<sockaddr *>(&addr), &len) == 0)
    {
        if (addr.ss_family == AF_INET)
        {
            struct sockaddr_in *in_addr = reinterpret_cast<sockaddr_in *>(&addr);
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &in_addr->sin_addr, ipstr, sizeof(ipstr));
            LOG_TRA << "Local address: " << ipstr << ":" << ntohs(in_addr->sin_port);
        }
        else if (addr.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *in6_addr = reinterpret_cast<sockaddr_in6 *>(&addr);
            char ipstr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &in6_addr->sin6_addr, ipstr, sizeof(ipstr));
            LOG_TRA << "Local address: " << ipstr << ":" << ntohs(in6_addr->sin6_port);
        }
    }
    else
    {
        std::cerr << "Could not retrieve local address info." << std::endl;
    }
}

void sst::Socket::SetSocketInfo(std::unique_ptr<SST_SocketInfo> tmp)
{
    std::lock_guard<std::mutex> lock(gate);
    info = std::move(tmp);
}

std::unique_ptr<sst::SST_SocketInfo> sst::Socket::GetSocketInfo() const
{
    std::lock_guard<std::mutex> lock(gate);
    if (!info)
    {
        std::cerr << "GetSocketInfo called on uninitialized socket" << std::endl;
        return nullptr;
    }
    // Return a copy of the SocketInfo; dup() the fd so the copy
    // can be destroyed independently without closing the original socket.
    auto copy_info = std::make_unique<SST_SocketInfo>();
    copy_info->sock = (info->sock != -1) ? dup(info->sock) : -1;
    if (info->sock != -1 && copy_info->sock == -1)
    {
        std::cerr << "Failed to dup socket fd in GetSocketInfo" << std::endl;
        return nullptr;
    }
    copy_info->len = info->len;
    if (info->addr)
    {
        copy_info->addr = SST_SocketInfo::AllocAddr(info->addr.get(), info->len);
        if (!copy_info->addr)
        {
            std::cerr << "Failed to allocate memory for GetSocketInfo" << std::endl;
            return nullptr;
        }
    }
    return copy_info;
}

int sst::Socket::get_fd() const {
    return info ? info->sock : -1;
}

int sst::Socket::GetPeerName(SST_SocketInfo *peer) const
{
    if (!info || info->sock == -1 || !peer)
    {
        std::cerr << "Invalid socket info or peer info" << std::endl;
        return -1;
    }

    struct sockaddr_storage addr_store;
    socklen_t addr_len = sizeof(addr_store);

    if (getpeername(info->sock, reinterpret_cast<sockaddr *>(&addr_store), &addr_len) == -1)
    {
        std::cerr << "Failed to get peer name" << std::endl;
        return -1;
    }

    // Allocate memory for the specific address type
    peer->len = addr_len;
    peer->addr = SST_SocketInfo::AllocAddr(&addr_store, addr_len);
    if (!peer->addr)
    {
        std::cerr << "Failed to allocate memory for peer address" << std::endl;
        return -1;
    }

    return 0;
}

int sst::Socket::CreateAddr(SST_SOCK_DOMAIN domain, const char *host_or_path, int port, void **addr, int *len)
{
    if (domain == SST_SOCK_INET)
    {
        auto *in_addr = static_cast<sockaddr_in *>(malloc(sizeof(sockaddr_in)));
        if (!in_addr)
        {
            std::cerr << "Failed to allocate memory for IPv4 address" << std::endl;
            return -1;
        }
        in_addr->sin_family = AF_INET;
        in_addr->sin_port = htons(port);
        if (inet_pton(AF_INET, host_or_path, &in_addr->sin_addr) != 1)
        {
            free(in_addr);
            std::cerr << "Invalid IPv4 address: " << host_or_path << std::endl;
            return -1;
        }
        *addr = in_addr; // Assign allocated memory to the output pointer [2]
        *len = sizeof(struct sockaddr_in);
    }
    else if (domain == SST_SOCK_INET6)
    {
        auto *in6_addr = static_cast<sockaddr_in6 *>(malloc(sizeof(sockaddr_in6)));
        if (!in6_addr)
        {
            std::cerr << "Failed to allocate memory for IPv6 address" << std::endl;

            return -1;
        }
        in6_addr->sin6_family = AF_INET6;
        in6_addr->sin6_port = htons(port);
        if (inet_pton(AF_INET6, host_or_path, &in6_addr->sin6_addr) != 1)
        {
            free(in6_addr);
            std::cerr << "Invalid IPv6 address: " << host_or_path << std::endl;
            return -1;
        }
        *addr = in6_addr;
        *len = sizeof(struct sockaddr_in6);
    }
    else
    {
        std::cerr << "Unsupported socket domain" << std::endl;
        return -1;
    }
    return 0;
}

sst::ClientSocket::ClientSocket(std::unique_ptr<SST_SocketInfo> info)
{
    SetSocketInfo(std::move(info));
}

// Implementation of ClientSocket class methods
sst::ClientSocket::ClientSocket(SST_SOCK_DOMAIN domain, const char *host_or_path, int port)
{
    SST_SocketInfo *info = nullptr;
    if (SocketClientOpen(&info, domain, host_or_path, port) == 0 && info != nullptr)
    {
        SetSocketInfo(std::unique_ptr<SST_SocketInfo>(info));
        LOG_TRA << "ClientSocket created with FD: " << info->sock;
    }
    else
    {
        std::cerr << "Failed to create ClientSocket for host: " << host_or_path << ", port: " << port << std::endl;
    }
}

sst::ClientSocket::~ClientSocket() {}

int sst::ClientSocket::Connect()
{
    if (info == nullptr)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    return sst::ClientSocket::SocketClientConnect(info.get());
}

int sst::ClientSocket::SocketClientOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port)
{
    auto new_info = std::make_unique<SST_SocketInfo>();
    void *raw_addr = nullptr;
    int addr_len = 0;

    // Allocate address via static helper [2]
    if (sst::Socket::CreateAddr(domain, host_or_path, port, &raw_addr, &addr_len) == -1)
    {
        std::cerr << "Failed to create address for ClientSocket" << std::endl;
        return -1;
    }
    new_info->addr.reset(static_cast<sockaddr *>(raw_addr));
    new_info->len = addr_len;

    // Initialize socket [1]
    new_info->sock = socket(domain, SOCK_STREAM, 0);
    if (new_info->sock == -1)
    {
        std::cerr << "Failed to create socket for ClientSocket" << std::endl;
        return -1;
    }

    *info = new_info.release(); // Transfer ownership to the caller
    LOG_TRA << "Client socket opened with FD: " << (*info)->sock;
    return 0;
}

int sst::ClientSocket::SocketClientConnect(SST_SocketInfo *info)
{
    if (!info || info->sock == -1 || !info->addr)
    {
        std::cerr << "Invalid socket info" << std::endl;
        return -1;
    }
    return connect(info->sock, info->addr.get(), info->len); // Standard connection [1]
}

// Implementation of ServerSocket class methods
sst::ServerSocket::ServerSocket(SST_SOCK_DOMAIN domain, const char *host, int port)
{
    SST_SocketInfo *raw_info = nullptr;
    if (sst::ServerSocket::SocketServerOpen(&raw_info, domain, host, port) == 0)
    {
        SetSocketInfo(std::unique_ptr<SST_SocketInfo>(raw_info));
        LOG_TRA << "ServerSocket created with FD: " << raw_info->sock;
    }
    else
    {
        std::cerr << "Failed to create ServerSocket for host: " << host << ", port: " << port << std::endl;
    }
}

sst::ServerSocket::~ServerSocket() {}

int sst::ServerSocket::SocketServerOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port)
{
    auto new_info = std::make_unique<SST_SocketInfo>();
    void *raw_addr = nullptr;
    int addr_len = 0;

    if (sst::Socket::CreateAddr(domain, host_or_path, port, &raw_addr, &addr_len) == -1)
    {
        std::cerr << "Failed to create address for ServerSocket" << std::endl;
        return -1;
    }
    new_info->addr.reset(static_cast<sockaddr *>(raw_addr));
    new_info->len = addr_len;

    new_info->sock = socket(domain, SOCK_STREAM, 0);
    if (new_info->sock == -1)
    {
        std::cerr << "Failed to create socket for ServerSocket" << std::endl;
        return -1;
    }

    // Bind and listen logic [1]
    if (bind(new_info->sock, new_info->addr.get(), new_info->len) == -1)
    {
        std::cerr << "Failed to bind socket for ServerSocket" << std::endl;
        return -1;
    }
    if (listen(new_info->sock, 5) == -1)
    {
        std::cerr << "Failed to listen on socket for ServerSocket" << std::endl;
        return -1;
    }

    *info = new_info.release();
    LOG_TRA << "Server socket opened and listening with FD: " << (*info)->sock;
    return 0;
}

int sst::ServerSocket::SocketServerAccept(SST_SocketInfo *info, SST_SocketInfo *peer)
{
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);

    int newsock = accept(info->sock, reinterpret_cast<sockaddr *>(&ss), &slen);
    if (newsock == -1)
    {
        std::cerr << "Failed to accept connection on ServerSocket" << std::endl;
        return -1;
    }

    peer->sock = newsock;
    peer->len = slen;

    peer->addr = sst::SST_SocketInfo::AllocAddr(&ss, slen);
    if (!peer->addr)
    {
        std::cerr << "Failed to allocate memory for accepted peer address" << std::endl;
        close(newsock);
        return -1;
    }
    LOG_TRA << "Accepted new connection on ServerSocket with FD: " << newsock;
    return 0;
}

int sst::ServerSocket::Accept(sst::ServerSocket &acceptedSocket)
{
    if (!info)
    {
        std::cerr << "Invalid socket info for accepting connection" << std::endl;
        return -1;
    }
    auto peer_info = std::make_unique<SST_SocketInfo>();
    if (sst::ServerSocket::SocketServerAccept(info.get(), peer_info.get()) == 0)
    {
        acceptedSocket.SetSocketInfo(std::move(peer_info));
        return 0;
    }
    std::cerr << "Failed to accept connection on ServerSocket" << std::endl;
    return -1;
}

// Implementation of EndPointSocket class methods
sst::EndPointSocket::EndPointSocket(SST_SOCK_DOMAIN domain, const char *host, int port)
{
    SST_SocketInfo *raw_info = nullptr;
    if (sst::EndPointSocket::SocketEndPointOpen(&raw_info, domain, host, port) == 0)
    {
        SetSocketInfo(std::unique_ptr<SST_SocketInfo>(raw_info));
        LOG_TRA << "EndPointSocket created with FD: " << raw_info->sock;
    }
    else
    {
        std::cerr << "Failed to create EndPointSocket for host: " << host << ", port: " << port << std::endl;
    }
}

sst::EndPointSocket::~EndPointSocket() {}

int sst::EndPointSocket::SocketEndPointOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port)
{
    // Use unique_ptr to handle automatic cleanup if the function returns early
    auto new_info = std::make_unique<SST_SocketInfo>();

    void *raw_addr = nullptr;
    int addr_len = 0;

    // CreateAddr allocates memory via malloc [2]
    if (sst::Socket::CreateAddr(domain, host_or_path, port, &raw_addr, &addr_len) == -1)
    {
        std::cerr << "Failed to create address for EndPointSocket" << std::endl;
        return -1; // new_info is automatically deleted here
    }

    // Transfer ownership of the malloc'd address to the unique_ptr in SST_SocketInfo
    new_info->addr.reset(static_cast<sockaddr *>(raw_addr));
    new_info->len = addr_len;

    new_info->sock = socket(domain, SOCK_STREAM, 0);
    if (new_info->sock == -1)
    {
        std::cerr << "Failed to create socket for EndPointSocket" << std::endl;
        return -1; // new_info (and its addr) are automatically deleted here
    }

    *info = new_info.release();
    LOG_TRA << "EndPoint socket opened with FD: " << (*info)->sock;
    return 0;
}