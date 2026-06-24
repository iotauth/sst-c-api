#include "ssl_socket.hpp"

#include <mutex>

namespace sst {

// Initialize static members
SSL_CTX* SSL_Socket::client_ctx_ = nullptr;
SSL_CTX* SSL_Socket::server_ctx_ = nullptr;
static std::once_flag ssl_init_flag;

void SSL_Socket::InitOpenSSL() {
    std::call_once(ssl_init_flag, []() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    });
}

SSL* SSL_Socket::CreateSsl(SSL_CTX* ctx) {
    if (!ctx) return nullptr;
    return SSL_new(ctx);
}

SSL_Socket::SSL_Socket() : ssl_(nullptr) { InitOpenSSL(); }

SSL_Socket::~SSL_Socket() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
}

SSL_Socket::SSL_Socket(SSL_Socket&& other) noexcept : ssl_(other.ssl_) {
    other.ssl_ = nullptr;
}

SSL_Socket& SSL_Socket::operator=(SSL_Socket&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        ssl_ = other.ssl_;
        other.ssl_ = nullptr;
    }
    return *this;
}

int SSL_Socket::InitClientContext(const char* cert_file, const char* key_file,
                                  const char* ca_file) {
    InitOpenSSL();
    if (client_ctx_) return 0;

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;

    if (ca_file && SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (cert_file && key_file) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1 ||
            SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(ctx);
            return -1;
        }
    }

    client_ctx_ = ctx;
    return 0;
}

int SSL_Socket::InitServerContext(const char* cert_file, const char* key_file,
                                  const char* ca_file) {
    InitOpenSSL();
    if (server_ctx_) return 0;

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return -1;

    if (!cert_file || !key_file) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    if (ca_file && SSL_CTX_load_verify_locations(ctx, ca_file, nullptr) != 1) {
        SSL_CTX_free(ctx);
        return -1;
    }

    server_ctx_ = ctx;
    return 0;
}

int SSL_Socket::Connect(SST_SOCK_DOMAIN domain, const char* host_or_path,
                        int port) {
    void* addr = nullptr;
    int len = 0;
    if (Socket::CreateAddr(domain, host_or_path, port, &addr, &len) != 0) {
        return -1;
    }

    // We'll use the base class mechanics if possible.
    // But SSL_Socket doesn't have a constructor that takes an existing FD
    // easily via public API. We'll manually create one and then set it into our
    // info.

    int sock = ::socket(domain, SOCK_STREAM, 0);
    if (sock < 0) {
        free(addr);
        return -1;
    }

    if (::connect(sock, static_cast<struct sockaddr*>(addr), len) != 0) {
        ::close(sock);
        free(addr);
        return -1;
    }
    free(addr);

    // Wrap this socket in our SSL_Socket.
    auto new_info = std::make_unique<SST_SocketInfo>();
    new_info->sock = sock;
    new_info->len = len;
    SetSocketInfo(std::move(new_info));

    if (!client_ctx_) {
        return -1;  // Client context must be initialized before Connect.
    }

    ssl_ = CreateSsl(client_ctx_);
    if (!ssl_) return -1;

    SSL_set_fd(ssl_, get_fd());

    if (SSL_connect(ssl_) <= 0) {
        return -1;
    }

    return 0;
}

int SSL_Socket::AcceptSecure(ServerSocket& server) {
    // We're using a raw accept here to avoid the type mismatch.
    int server_fd = server.get_fd();
    struct sockaddr_storage client_addr;
    socklen_t len = sizeof(client_addr);

    int client_fd = ::accept(server_fd, (struct sockaddr*)&client_addr, &len);
    if (client_fd < 0) {
        return -1;
    }

    // Update this socket's info with the new connection.
    auto new_info = std::make_unique<SST_SocketInfo>();
    new_info->sock = client_fd;
    new_info->len = len;
    SetSocketInfo(std::move(new_info));

    if (!server_ctx_) {
        return -1;  // Server context must be pre-initialized.
    }

    ssl_ = CreateSsl(server_ctx_);
    if (!ssl_) return -1;

    SSL_set_fd(ssl_, get_fd());

    if (SSL_accept(ssl_) <= 0) {
        return -1;
    }

    return 0;
}

int SSL_Socket::Read(char* buf, int nbytes) const {
    if (!ssl_) {
        return Socket::Read(buf, nbytes);
    }

    // Use const_cast to call the non-const SSL_read.
    int ret = SSL_read(const_cast<SSL*>(ssl_), buf, nbytes);
    if (ret <= 0) {
        return -1;
    }
    return ret;
}

int SSL_Socket::Write(char* buf, int nbytes) {
    if (!ssl_) {
        return Socket::Write(buf, nbytes);
    }

    int ret = SSL_write(ssl_, buf, nbytes);
    if (ret <= 0) {
        return -1;
    }
    return ret;
}

}  // namespace sst
