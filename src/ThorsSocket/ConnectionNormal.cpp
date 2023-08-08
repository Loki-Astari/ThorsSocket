#include "ConnectionNormal.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"

// #include <sys/types.h>

using namespace ThorsAnvil::ThorsSocket;

namespace Utility = ThorsAnvil::Utility;

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectionNormal::ConnectionNormal(int fd)
    : Connection(fd)
    , fd(fd)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectionNormal::~ConnectionNormal()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::accept()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::connect(std::string const& host, int port)
{
    SocketAddrIn serverAddr{};

    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);

    HostEnt* serv;
    while (true)
    {
        serv = ::gethostbyname(host.c_str());
        if (serv == nullptr)
        {
            if (h_errno == TRY_AGAIN)
            {
                continue;
            }
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionNormal::",
                             "connect",
                             "::gethostbyname(): ", Utility::systemErrorMessage());
        }
        break;
    }
    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    if (connectWrapper(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        //close();
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::ConnectionNormal::",
                                 "connect",
                                 "::connect(): ", Utility::systemErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOInfo ConnectionNormal::read(char* buffer, std::size_t size)
{
    return readWrapper(fd, buffer, size);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOInfo ConnectionNormal::write(char const* buffer, std::size_t size)
{
    return writeWrapper(fd, buffer, size);
}
