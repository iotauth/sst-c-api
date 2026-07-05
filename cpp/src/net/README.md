# Network Layer — `sockets` & `ssl_socket`

This directory provides RAII wrappers around POSIX sockets and OpenSSL TLS. All types live in the `sst` namespace.

## Files

| File | Purpose |
|---|---|
| [`sockets.hpp`](sockets.hpp) / [`sockets.cpp`](sockets.cpp) | Base socket classes — `Socket`, `ClientSocket`, `ServerSocket`, `EndPointSocket`. Pure TCP, no encryption. |
| [`ssl_socket.hpp`](ssl_socket.hpp) / [`ssl_socket.cpp`](ssl_socket.cpp) | TLS layer on top of `Socket` using OpenSSL. Provides client and server secure sockets via `SSL_Socket`. |

## Architecture

```mermaid
graph TD
    Socket["Socket (base)\nRead/Write/Poll"] --> ClientSocket["ClientSocket\nConnect()"]
    Socket --> ServerSocket["ServerSocket\nAccept()"]
    Socket --> EndPointSocket["EndPointSocket\nGeneral purpose"]
    Socket --> SSL_Socket["SSL_Socket\nTLS on top of Socket"]
```

### `sockets.hpp` — Base TCP sockets

**`SST_SocketInfo`** — RAII container for a raw file descriptor and its address. Closes the FD in the destructor; manages `sockaddr` address storage with `std::make_unique<uint8_t[]>` and a custom deleter that calls `delete[]` on a `uint8_t*`. All allocation is exception-safe — no `malloc` or `free` anywhere in the layer.

**`Socket`** (abstract base)
- Thread-safe I/O: every read/write is guarded by a `mutable std::mutex gate_`.
- Blocking `Read()` / `Write()` — standard POSIX calls.
- Timeout-aware `NonBlockingRead()` / `NonBlockingWrite()` — temporarily sets `O_NONBLOCK`, falls back to `poll()` if the operation would block, then restores the original flags.
- `Pending()` returns bytes available via `ioctl(FIONREAD)`.
- `ReadyToReadTimeOut(ms)` uses `poll()` with a timeout; `ReadyToRead()` blocks indefinitely.

**`ClientSocket`** — connects to a remote host/port. Constructor takes either an existing `SST_SocketInfo` or `(domain, host, port)`. Call `Connect()` after construction.

**`ServerSocket`** — binds and listens on a local address. Call `Accept(ServerSocket&)` to block until a new connection arrives; the accepted socket is populated into the argument.

**`EndPointSocket`** — general-purpose unconnected endpoint (useful for UDP or raw sockets).

### `ssl_socket.hpp` — TLS over TCP

**`SSL_Socket`** extends `Socket` with an OpenSSL `SSL*` handle:
- **Client mode**: call `InitClientContext(cert, key, ca)` once per process, then `Connect(domain, host, port)`. Creates a plain TCP socket internally and performs the TLS handshake.
- **Server mode**: call `InitServerContext(cert, key, ca)` once per process, then `AcceptSecure(ServerSocket&)` on a listening server socket.
- `Read()` / `Write()` are overridden to use `SSL_read` / `SSL_write` when an SSL session is active; they fall back to the base class otherwise.

**Key details:**
- OpenSSL library init (`SSL_library_init`, etc.) runs exactly once via `std::call_once`.
- Client and server contexts are process-wide singletons — initialized lazily on first call, then reused. Calling `InitClientContext` twice is a no-op (returns 0).
- The class is **move-only** (copy constructor/assignment deleted); move semantics transfer the `SSL*` handle cleanly.

## Pitfalls

1. **Non-blocking flag restoration**: `NonBlockingRead()` and `NonBlockingWrite()` temporarily set `O_NONBLOCK`. If an exception occurs between setting and restoring, the socket stays non-blocking — wrap calls in try/catch if you depend on blocking mode afterward.
2. **`const_cast` in SSL_Socket::Read**: The `SSL_read()` call uses `const_cast<SSL*>` because OpenSSL's API is not const-correct. Don't modify the SSL object through a "const" path.
3. **Context initialization order**: You must call `InitClientContext` / `InitServerContext` before `Connect` / `AcceptSecure`, or they return `-1`.
4. **FD duplication in GetSocketInfo**: Returns a copy with a duplicated FD (`dup()`). Callers should not assume the returned fd is the same as the original — it's an independent OS-level handle.

## Usage Example

```cpp
// Client connection (plain TCP)
sst::ClientSocket client(AF_INET, "127.0.0.1", 8080);
client.Connect();
char buf[1024];
int n = client.Read(buf, sizeof(buf));

// Server-side accept
sst::ServerSocket server(AF_INET, nullptr, 8080);
sst::ClientSocket accepted(nullptr);
server.Accept(accepted);

// TLS connection
sst::SSL_Socket ssl;
ssl.InitClientContext("cert.pem", "key.pem", "ca.pem");
ssl.Connect(AF_INET, "example.com", 443);
ssl.Write(data, len);
```
