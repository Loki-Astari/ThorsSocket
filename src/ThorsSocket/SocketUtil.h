#ifndef THORSANVIL_THORSSOCKET_SOCKET_UTIL_H
#define THORSANVIL_THORSSOCKET_SOCKET_UTIL_H

#include "ThorsSocketConfig.h"
#include "SecureSocketUtil.h"

#include <cstddef>
#include <string_view>

#ifdef  __WINNT__
#include <winsock2.h>
#include <windows.h>
#define SOCKET_TYPE             SOCKET
#define THOR_BINARY             _O_BINARY
#else
#define SOCKET_TYPE             int
#define THOR_BINARY             0
#endif

namespace ThorsAnvil::ThorsSocket
{

using YieldFunc     = std::function<bool()>;

struct IOData
{
    std::size_t     dataSize;
    bool            stillOpen;
    bool            blocked;
};

enum class FileMode     {Read, WriteAppend, WriteTruncate};
enum class Blocking     {No, Yes};
enum class Mode         {Read, Write};
enum class DeferAccept  {No, Yes};

struct FileInfo
{
    std::string_view    fileName;
    FileMode            mode;
};

struct ExecutableFile
{
    std::string                 fileName;
    std::vector<std::string>    arguments;
};

struct PipeInfo
{};

struct SocketInfo
{
    std::string_view    host;
    int                 port;
};

struct SocketService
{
    std::string_view    host;
    std::string_view    service;
};

struct ServerInfo
{
    int                 port;
};

struct OpenSocketInfo
{
    SOCKET_TYPE         fd;
};

// Want this to be movable (nice to have it copyable).
// This means ctx as a reference was not a valid design.
// Still want to take the CTX as a reference but will take store a non owning pointer.
// This allows this information to be moved. But this requires we write some extra code
// and break the old interface (in a minor way).
struct SSocketInfo: public SocketInfo
{
    SSocketInfo(std::string_view host, int port, SSLctx const& ctx, DeferAccept defer)
        : SocketInfo{host, port}
        , ctxPtr{&ctx}
        , defer{defer}
    {}
    SSocketInfo(SSocketInfo const&)             = default;
    SSocketInfo(SSocketInfo&&)                  = default;
    SSocketInfo& operator=(SSocketInfo const&)  = default;
    SSocketInfo& operator=(SSocketInfo&&)       = default;
    SSLctx const*       ctxPtr;
    SSLctx const&       ctx() const             {return *ctxPtr;}
    DeferAccept         defer;
};

// Want this to be movable (nice to have it copyable).
// This means ctx as a reference was not a valid design.
// Still want to take the CTX as a reference but will take store a non owning pointer.
// This allows this information to be moved. But this requires we write some extra code
// and break the old interface (in a minor way).
struct SSocketService: public SocketService
{
    SSocketService(std::string_view host, std::string service, SSLctx const& ctx, DeferAccept defer)
        : SocketService{host, service}
        , ctxPtr{&ctx}
        , defer{defer}
    {}
    SSocketService(SSocketService const&)             = default;
    SSocketService(SSocketService&&)                  = default;
    SSocketService& operator=(SSocketService const&)  = default;
    SSocketService& operator=(SSocketService&&)       = default;
    SSLctx const*       ctxPtr;
    SSLctx const&       ctx() const             {return *ctxPtr;}
    DeferAccept         defer;
};

struct SServerInfo: public ServerInfo
{
    SSLctx              ctx;
};

struct OpenSSocketInfo: public OpenSocketInfo
{
    SSLctx const&       ctx;
    DeferAccept         defer;
};

}

#endif
