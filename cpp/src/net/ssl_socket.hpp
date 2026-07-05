/** 
 * @file ssl_socket.hpp
 * @brief SSL/TLS wrapper over the Socket class using OpenSSL.
 * @details
 * Provides client and server side secure sockets. The API mirrors the
 * non‑secure `Socket` methods where possible (Connect, Accept, Read,
 * Write) but internally performs an SSL handshake and uses `SSL_read`
 * / `SSL_write`.
 * @author Salomon Lee / Claude - nemotron-3-namo:30b, gemma4:26b
 * @date 2026-06-22
 */
#ifndef SSL_SOCKET_H
#define SSL_SOCKET_H

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "sockets.hpp"

namespace sst {
/**
 * @class SSL_Socket
 * @brief Secure socket based on OpenSSL.
 *
 * Inherits from `Socket` and adds an `SSL*` handle. The class can be used as a
 * client (calling Connect) or as a server side accepted connection (using
 * AcceptSecure on a listening `ServerSocket`). All I/O is performed through
 * the SSL layer.
 */
class SSL_Socket : public Socket {
   public:
    /** Construct an empty SSL socket. */
    SSL_Socket();

    /** Destructor releases SSL resources. */
    ~SSL_Socket() override;

    // Disallow copying – SSL objects are not copyable.
    SSL_Socket(const SSL_Socket&) = delete;
    SSL_Socket& operator=(const SSL_Socket&) = delete;

    // Allow moving.
    SSL_Socket(SSL_Socket&&) noexcept;
    SSL_Socket& operator=(SSL_Socket&&) noexcept;

    /**
     * @brief Initialise a client‑side SSL context.
     *
     * Must be called before `Connect`. The caller can optionally provide a
     * certificate/key for mutual authentication and a CA file to verify the
     * server. If all arguments are nullptr, the default system trust store is
     * used.
     */
    int InitClientContext(const char* cert_file = nullptr,
                          const char* key_file = nullptr,
                          const char* ca_file = nullptr);

    /**
     * @brief Initialise a server‑side SSL context.
     *
     * Must be called before `AcceptSecure`. The certificate and private key are
     * mandatory for a TLS server. An optional CA file can be supplied to
     * request client certificates.
     */
    int InitServerContext(const char* cert_file, const char* key_file,
                          const char* ca_file = nullptr);

    /**
     * @brief Establish a TLS connection to a remote endpoint.
     *
     * This method creates a plain TCP socket (using the base class helpers) and
     * then performs an SSL handshake. The socket is left in a connected state
     * on success.
     */
    int Connect(SST_SOCK_DOMAIN domain, const char* host_or_path, int port);

    /**
     * @brief Accept a TLS connection from a listening server socket.
     */
    int AcceptSecure(ServerSocket& server);

    // Override I/O to use SSL when active.
    int Read(char* buf, int nbytes) const override;
    int Write(char* buf, int nbytes) override;

   private:
    /** OpenSSL SSL object bound to the socket's file descriptor. */
    SSL* ssl_;

    /** Shared client context – lazily created on first InitClientContext call.
     */
    static SSL_CTX* client_ctx_;
    /** Shared server context – lazily created on first InitServerContext call.
     */
    static SSL_CTX* server_ctx_;

    /** One‑time OpenSSL library initialisation. */
    static void InitOpenSSL();

    /** Helper to create an `SSL*` from a given context. */
    SSL* CreateSsl(SSL_CTX* ctx);
};

}  // namespace sst

#endif  // SSL_SOCKET_H
