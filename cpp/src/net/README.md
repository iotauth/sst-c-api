# TCP socket wrappers

`sockets.hpp` provides `sst::Socket`, `sst::ClientSocket`, and
`sst::ServerSocket`. They own POSIX TCP descriptors and transfer plain bytes.
For authenticated, encrypted communication, use `SST_API` and `SST_Session`
from [`api.hpp`](../api.hpp).

- `ClientSocket(domain, host, port)` opens a socket for a numeric IPv4 or IPv6
  address. Call `Connect()` to establish the connection.
- `ServerSocket(domain, host, port)` binds and listens. Port 0 selects an
  available port. `Accept(ServerSocket&)` replaces the destination's socket
  only after accepting a connection successfully.
- Failed socket construction leaves `get_fd()` equal to -1. `Connect()` and
  `Accept()` return 0 on success and -1 on failure.
- `Read()` waits for the requested byte count, EOF, or an error. `Write()` makes
  one POSIX write and may return fewer bytes than requested.

`SST_SocketInfo` owns both its descriptor and a copy of its address.
`SetSocketInfo()` transfers ownership, closing the previous descriptor.
`GetSocketInfo()` copies the address and uses `dup()` for the descriptor:
closing either owner leaves the other handle open, but they share the same
connection and I/O state. `get_fd()` only borrows the descriptor.

Writes and ownership changes use a mutex. Reads, connection setup, and borrowed
handles require coordination by the caller; finish I/O before closing or
replacing a socket.

## Example

```cpp
sst::ServerSocket server(sst::SST_SOCK_INET, "127.0.0.1", 8080);
if (server.get_fd() == -1) return 1;

// Accept replaces this temporary listener and closes its descriptor.
sst::ServerSocket accepted(sst::SST_SOCK_INET, "127.0.0.1", 0);
if (server.Accept(accepted) != 0) return 1;

char buffer[1024];
int length = accepted.Read(buffer, sizeof(buffer));
// Read waits for 1024 bytes, EOF, or an error; it does not delimit messages.
```
