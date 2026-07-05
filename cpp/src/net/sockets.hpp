/**
 * @file Sockets.h
 * @brief A high-level C++ wrapper for POSIX socket operations.
 * @author Salomon Lee
 * @date 2026-03-15
 */
#ifndef SOCKET_H
#define SOCKET_H

#include <mutex>
#include <string>
#include <memory>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>

namespace sst
{
/**
 * @brief Supported network domains for socket creation.
 * Maps directly to system AF_* constants.
 */
enum SST_SOCK_DOMAIN
{
    SST_SOCK_INET = AF_INET,
    SST_SOCK_INET6 = AF_INET6,
    SST_SOCK_UNIX = AF_UNIX
};

/**
 * @struct SST_SocketInfo
 * @brief Container for raw socket data and address information.
 *
 * Uses RAII (Resource Acquistion Is Instantiation) to ensure that the file descriptor is closed and the
 * allocated sockaddr memory is freed automatically when the struct
 * goes out of scope.
 */
struct SST_SocketInfo
{
    int sock;      ///< Raw file descriptor for the socket.
    socklen_t len; ///< Length of the address structure.

    /**
     * @brief Smart pointer managing the sockaddr lifecycle.
     * Uses a custom deleter to call free() on memory allocated via malloc.
     */
    std::unique_ptr<sockaddr, void (*)(sockaddr *)> addr;

    /**
     * @brief Constructor initializing an empty/invalid socket info.
     */
    SST_SocketInfo() : sock(-1), len(0), addr(nullptr, [](sockaddr *p)
                                              { free(p); })
    {
    }

    /**
     * @brief Destructor that closes the socket if it is open.
     */
    ~SST_SocketInfo()
    {
        if (sock != -1)
        {
            ::close(sock);
        }
    }

    /**
     * @brief Factory helper to allocate and copy a sockaddr into a managed unique_ptr.
     * @param src Pointer to the source address data.
     * @param length Size of the address structure in bytes.
     * @return A unique_ptr<sockaddr> with a free() deleter, or nullptr on failure.
     */
    static std::unique_ptr<sockaddr, void(*)(sockaddr*)> AllocAddr(const void* src, socklen_t length)
    {
        void* raw = malloc(length);
        if (!raw)
            return {nullptr, [](sockaddr* p){ free(p); }};
        memcpy(raw, src, length);
        return {static_cast<sockaddr*>(raw), [](sockaddr* p){ free(p); }};
    }
};

/**
 * @class Socket
 * @brief Base class providing core socket functionality and I/O operations.
 *
 * This class serves as a foundation for Client, Server, and EndPoint sockets,
 * providing thread-safe access to common operations like Read, Write, and Poll.
 */
class Socket
{
public:
    Socket();

    virtual ~Socket();

    /** @brief Manually close the underlying socket. */
    void Close();

    /**
     * @brief Returns the number of bytes available to be read from the socket.
     * @return Number of pending bytes, or -1 on error.
     */
    int Pending() const;

    /**
     * @brief Polls the socket to see if data is ready to be read within a timeout.
     * @param timeout Timeout in milliseconds.
     * @return true if data is available, false otherwise.
     */
    bool ReadyToReadTimeOut(int timeout) const;

    /** @brief Checks if data is ready to be read (non-blocking). */
    bool ReadyToRead() const;

    /**
     * @brief Standard blocking read operation.
     * @param buf Buffer to store data.
     * @param nbytes Number of bytes to read.
     * @return Number of bytes read, or -1 on error.
     */
    virtual int Read(char *buf, int nbytes) const;

    /**
     * @brief Standard blocking write operation.
     * @param buf Buffer containing data to send.
     * @param nbytes Number of bytes to write.
     * @return Number of bytes written, or -1 on error.
     */
    virtual int Write(char *buf, int nbytes);

    /**
     * @brief Reads from the socket with a specific timeout.
     * @param buf Buffer to store data.
     * @param size Maximum size to read.
     * @param timeout Timeout in milliseconds.
     * @return Number of bytes read, or -1/0 on timeout or error.
     */
    int NonBlockingRead(char *buf, int size, int timeout) const;

    /**
     * @brief Writes to the socket with a specific timeout.
     * @param buf Buffer containing data to send.
     * @param size Maximum size to write.
     * @param timeout Timeout in milliseconds.
     * @return Number of bytes written, or -1/0 on timeout or error.
     */
    int NonBlockingWrite(char *buf, int size, int timeout);

    /** @brief Outputs the current socket state to the console for debugging. */
    void DebugDump() const;

    /**
     * @brief Transfers ownership of a SocketInfo structure to this instance.
     * @param tmp Unique pointer to the SocketInfo.
     */
    void SetSocketInfo(std::unique_ptr<SST_SocketInfo> tmp);

    /**
     * @brief Retrieves a copy of the current SocketInfo.
     * @return Unique pointer to a new SocketInfo containing the same data aka copy of the smartpointer .
     */
    std::unique_ptr<SST_SocketInfo> GetSocketInfo() const;
    
    // Returns the raw file descriptor of the underlying socket, or -1 if not initialized.
    int get_fd() const;

    /**
     * @brief Retrieves the address of the connected peer.
     * @param peer Pointer to a SocketInfo struct to be populated.
     * @return 0 on success, -1 on failure.
     */
    int GetPeerName(SST_SocketInfo *peer) const;

    /**
     * @brief Static helper to create and populate a sockaddr structure.
     * @param domain The network domain (IPv4, IPv6, Unix).
     * @param host_or_path The IP address or Unix socket path.
     * @param port The port number (ignored for Unix sockets).
     * @param addr [out] Pointer to the allocated address structure.
     * @param len [out] Pointer to the length of the created address.
     * @return 0 on success, non-zero on error.
     */
    static int CreateAddr(SST_SOCK_DOMAIN domain, const char *host_or_path, int port, void **addr, int *len);

protected:
    std::unique_ptr<SST_SocketInfo> info; ///< Managed socket resources.
    mutable std::mutex gate;              ///< Mutex for thread-safe socket operations.
};

/**
 * @class ClientSocket
 * @brief Specialization for client-side connection establishment.
 */
class ClientSocket : public Socket
{
public:
    /**
     * @brief Constructs a client socket with an existing SocketInfo.
     * @param info Unique pointer to a pre-populated SocketInfo structure.
     */
    ClientSocket(std::unique_ptr<SST_SocketInfo> info);
    
    /**
     * @brief Constructs a client socket.
     * @param domain Network domain.
     * @param host_or_path Destination host or path.
     * @param port Destination port.
     */
    ClientSocket(SST_SOCK_DOMAIN domain, const char *host_or_path, int port);
    virtual ~ClientSocket();

    /** @brief Initiates connection to the target specified in constructor. @return 0 on success. */
    int Connect();

    /** @brief Internal method to open a client socket. */
    int SocketClientOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port);

    /** @brief Internal method to connect a prepared socket info. */
    int SocketClientConnect(SST_SocketInfo *info);
};

/**
 * @class ServerSocket
 * @brief Specialization for server-side listening and accepting.
 */
class ServerSocket : public Socket
{
public:
    /**
     * @brief Constructs a server socket and binds to the specified address/port.
     */
    ServerSocket(SST_SOCK_DOMAIN domain, const char *host_or_path, int port);
    virtual ~ServerSocket();

    /**
     * @brief Blocks until a new connection is received.
     * @param acceptedSocket A Socket instance to be populated with the new connection.
     * @return 0 on success.
     */
    int Accept(ServerSocket &acceptedSocket);

    /** @brief Internal method to set up the listener socket. */
    int SocketServerOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port);

    /** @brief Internal method to accept a raw connection. */
    int SocketServerAccept(SST_SocketInfo *info, SST_SocketInfo *peer);
};

/**
 * @class EndPointSocket
 * @brief General purpose socket for connectionless or specific endpoint scenarios.
 */
class EndPointSocket : public Socket
{
public:
    EndPointSocket(SST_SOCK_DOMAIN domain, const char *host_or_path, int port);
    virtual ~EndPointSocket();

    /** @brief Internal method to open the endpoint. */
    int SocketEndPointOpen(SST_SocketInfo **info, SST_SOCK_DOMAIN domain, const char *host_or_path, int port);
};
}
#endif // SOCKET_H