/**
 * @file sockets.hpp
 * @brief Owning POSIX TCP sockets for SST clients and listeners.
 * @author Salomon Lee
 */
#ifndef SST_CPP_SOCKETS_HPP
#define SST_CPP_SOCKETS_HPP

#include <sys/socket.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>

namespace sst {

enum SST_SOCK_DOMAIN {
    SST_SOCK_INET = AF_INET,
    SST_SOCK_INET6 = AF_INET6,
};

/** @brief Owns a socket descriptor and a copy of its address. */
struct SST_SocketInfo {
    int sock;
    socklen_t len;
    std::unique_ptr<sockaddr, void (*)(sockaddr*)> addr;

    static void FreeAddr(sockaddr* p) {
        delete[] reinterpret_cast<std::byte*>(p);
    }

    SST_SocketInfo() : sock(-1), len(0), addr(nullptr, &FreeAddr) {}

    ~SST_SocketInfo() {
        if (sock != -1) {
            ::close(sock);
        }
    }

    // Address storage is copied as bytes and must use the matching deleter.
    static std::unique_ptr<sockaddr, void (*)(sockaddr*)> AllocAddr(
        const void* src, socklen_t length) {
        std::byte* raw = new (std::nothrow) std::byte[length];
        if (!raw) return {nullptr, &FreeAddr};
        std::memcpy(raw, src, length);
        return {reinterpret_cast<sockaddr*>(raw), &FreeAddr};
    }
};

/**
 * @brief Owns a TCP socket; destruction closes its descriptor.
 *
 * Writes and ownership changes are serialized. Reads do not take that lock:
 * callers must finish all I/O before closing or replacing the socket.
 * These operations transfer plain bytes; SST_Session handles secure framing.
 */
class Socket {
   public:
    Socket() = default;
    virtual ~Socket();

    /** @brief Closes the socket. Safe to call again on a closed socket. */
    void Close();

    /**
     * @brief Reads until nbytes have arrived, EOF, or an error.
     * @return Bytes read (possibly fewer at EOF), 0 on EOF, or -1 on error.
     */
    virtual int Read(char* buf, int nbytes) const;

    /**
     * @brief Performs one blocking write; callers must handle partial writes.
     * @return Bytes written, or -1 on error.
     */
    virtual int Write(char* buf, int nbytes);

    /** @brief Takes ownership of the supplied info, closing the old socket. */
    void SetSocketInfo(std::unique_ptr<SST_SocketInfo> socket_info);

    /**
     * @brief Copies the address and duplicates the descriptor with dup().
     * The copy closes independently but shares the same connection and I/O
     * state. Returns nullptr if the socket is uninitialized or copying fails.
     */
    std::unique_ptr<SST_SocketInfo> GetSocketInfo() const;

    /** @brief Borrows the descriptor, or returns -1 if uninitialized. */
    int get_fd() const;

   protected:
    const std::unique_ptr<SST_SocketInfo>& get_info_ref() const { return info; }

   private:
    std::unique_ptr<SST_SocketInfo> info;
    mutable std::mutex gate;
};

/** @brief TCP client. A failed constructor leaves get_fd() equal to -1. */
class ClientSocket : public Socket {
   public:
    ClientSocket(std::unique_ptr<SST_SocketInfo> socket_info);
    // host must be a numeric IPv4 or IPv6 address matching domain.
    ClientSocket(SST_SOCK_DOMAIN domain, const char* host, int port);

    /** @brief Connects to the configured address; returns 0 or -1 on error. */
    int Connect();
};

/**
 * @brief Binds and listens on a numeric IPv4 or IPv6 address.
 * A failed constructor leaves get_fd() equal to -1. Port 0 lets the OS choose
 * an available port, which can be queried with getsockname(get_fd(), ...).
 */
class ServerSocket : public Socket {
   public:
    ServerSocket(SST_SOCK_DOMAIN domain, const char* host, int port);

    /**
     * @brief Accepts one connection, replacing acceptedSocket's old socket.
     * @return 0 on success, -1 on failure (acceptedSocket stays unchanged).
     */
    int Accept(ServerSocket& acceptedSocket);
};

}  // namespace sst
#endif  // SST_CPP_SOCKETS_HPP
