# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

ThorsSocket uses a custom autotools-based build system (ThorMaker). It is part of the ThorsAnvil monorepo and expects `THORSANVIL_ROOT` to point to the monorepo root (defaults to `../../`).

```bash
# Build (from repo root or src/ThorsSocket/)
make

# Run all tests
make test

# Run a specific test class
make test-ConnectionSocketTest.*

# Run a specific test method
make test-ConnectionSocketTest.MethodName

# Run test without rebuilding
make testrun.ConnectionSocketTest.*

# Debug a test
make debugrun.ConnectionSocketTest.*

# Clean
make clean
make veryclean    # deep clean including generated files
```

Dependencies: OpenSSL (crypto), ThorsLogging, ThorsSerialize (optional), ZLIB (optional). Tests use GoogleTest. Coverage minimum: 70%.

## Architecture

ThorsSocket provides async I/O over files, pipes, TCP sockets, and SSL/TLS sockets, exposed as `std::iostream`.

### Public API (3 classes)

- **`Socket`** — Client socket for reading/writing. Non-copyable, move-only. Supports yield callbacks for async/coroutine integration (`setReadYield`, `setWriteYield`).
- **`Server`** — Listening server that produces `Socket` objects via `accept()`. Also supports yield callbacks.
- **`SocketStream`** — Template wrapping `Socket` as `std::iostream` with 4KB input/output buffering via `SocketStreamBuffer`.

### Connection Hierarchy (internal polymorphic dispatch)

Socket/Server delegate to a polymorphic `ConnectionBase` hierarchy:

```
ConnectionBase
├── ConnectionClient
│   ├── FileDescriptor
│   │   ├── SimpleFile      (file I/O)
│   │   ├── Pipe            (pipe I/O)
│   │   └── SocketClient    (TCP)
│   │       └── SSocketClient (SSL/TLS)
│   └── SocketClient        (Windows variant)
└── ConnectionServer
    ├── SocketServer         (TCP listen)
    └── SSocketServer        (SSL/TLS listen)
```

### Variant-based Construction

Socket/Server are constructed via `std::variant` types (`SocketInit`/`ServerInit`) containing info structs: `FileInfo`, `PipeInfo`, `SocketInfo`, `SSocketInfo`, `ServerInfo`, `SServerInfo`. A visitor pattern builds the appropriate Connection subclass.

### Async Integration

Yield callbacks (`YieldFunc`) are the integration point for coroutines/event loops. When I/O would block, the yield function is called. Return `true` to retry, `false` to block until ready. This is how Nisse's coroutine-based server integrates.

### Header-Only Support

Every `.cpp` file is guarded by `THORS_SOCKET_HEADER_ONLY_INCLUDE` macro. Corresponding `.source` files exist for header-only compilation. Controlled by `ThorsSocketConfig.h` (generated at configure time).

## Source Layout

All library code: `src/ThorsSocket/`
All tests: `src/ThorsSocket/test/`
Test SSL certificates: `src/ThorsSocket/test/data/` (root-ca/, server/, client/)
Test mock infrastructure: `src/ThorsSocket/test/makedependency/`

## Namespace

```cpp
namespace ThorsAnvil::ThorsSocket {
    // Public: Socket, Server, SocketStream, SSLctx
    namespace ConnectionType {
        // Internal: SocketClient, SSocketClient, SimpleFile, Pipe, etc.
    }
}
```

## Platform Considerations

- Windows: Uses WinSock2 API, guarded by `__WINNT__`. Requires `-lws2_32 -lwsock32`.
- Unix: POSIX APIs (poll, socket, fcntl). Platform abstraction lives in `ConnectionUtil.h/cpp`.
- `HAS_UNIQUE_EWOULDBLOCK` config flag handles platforms where EAGAIN == EWOULDBLOCK.
