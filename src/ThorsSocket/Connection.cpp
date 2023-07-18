#include "Connection.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"

#include <sys/types.h>

using namespace ThorsAnvil::ThorsIO;

namespace Utility = ThorsAnvil::Utility;

void Connection::accept()
{}

void Connection::connect(int fd, std::string const& host, int port)
{
    SocketAddrIn serverAddr{};

    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    //serverAddr.sin_addr.s_addr  = inet_addr(host.c_str());

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
            ThorsLogAndThrow("ThorsAnvil::ThorsIO::Connection::",
                             "connect",
                             "::gethostbyname(): ", Utility::systemErrorMessage());
        }
        break;
    }
    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    if (::connectWrapper(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::Connection::",
                                 "connect",
                                 "::connect(): ", Utility::systemErrorMessage());
    }
#if 0
    makeSocketNonBlocking();
    SSLMethod   method(Common::SSLMethodType::Client);
    ctx     = std::make_unique<SSLctx>(method);
    ssl     = std::make_unique<SSLObj>(*ctx, getSocketId());
    ssl->connect();
#endif
}

IOInfo Connection::read(int fd, char* buffer, std::size_t size)
{
    return ::readWrapper(fd, buffer, size);
    // ssl->read(buffer + dataRead, size - dataRead);
}

IOInfo Connection::write(int fd, char const* buffer, std::size_t size)
{
    return ::writeWrapper(fd, buffer, size);
    // ssl->write(buffer + dataWritten, size - dataWritten);
}
