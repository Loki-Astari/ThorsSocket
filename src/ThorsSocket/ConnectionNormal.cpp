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
{
    if (fd == invalidSocketId)
    {
        // This object has been closed or moved.
        // So we don't need to call close.
        return;
    }

    try
    {
        close();
    }
    // Catch and drop any exceptions.
    // Logging so we know what happened.
    catch (std::exception const& e)
    {
        ThorsCatchMessage("ThorsAnvil::ThorsSocket::BaseSocket", "~BaseSocket", e.what());
    }
    catch (...)
    {
        ThorsCatchMessage("ThorsAnvil::ThorsSocket::BaseSocket", "~BaseSocket", "UNKNOWN");
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool ConnectionNormal::isValid() const
{
    return fd != invalidSocketId;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int ConnectionNormal::socketId() const
{
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::makeSocketNonBlocking()
{
    if (nonBlockingWrapper(fd) == -1)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                 "makeSocketNonBlocking",
                                 "::fcntl() ", Utility::systemErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::close()
{
    while (true)
    {
        if (closeWrapper(fd) == -1)
        {
            switch (errno)
            {
                case EBADF: fd = invalidSocketId;
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                                     "close"
                                                     "::close() ", fd, " ", Utility::systemErrorMessage());
                case EIO:   fd = invalidSocketId;
                            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::BaseSocket::",
                                             "close",
                                             "::close() ", fd, " ", Utility::systemErrorMessage());
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
                default:    fd = invalidSocketId;
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                                     "close",
                                                     "::close() ", fd, " ", Utility::systemErrorMessage());
            }
        }
        break;
    }
    fd = invalidSocketId;
}

#ifdef  __WINNT__
#define THOR_SHUTDOWN_WRITE     SD_SEND
#else
#define THOR_SHUTDOWN_WRITE     SHUT_WR
#endif
THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::shutdown()
{
    if (::shutdown(fd, THOR_SHUTDOWN_WRITE) != 0)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::Socket::DataSocket::",
                                 "putMessageClose",
                                 "::shutdown(): critical error: ", Utility::systemErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionNormal::bind(int port, int maxWaitingConnections)
{
    SocketAddrIn    serverAddr = {};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    serverAddr.sin_addr.s_addr  = INADDR_ANY;

    if (bindWrapper(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::bind() ", Utility::systemErrorMessage());
    }

    if (listnWrapper(fd, maxWaitingConnections) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::listen() ", Utility::systemErrorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int ConnectionNormal::accept()
{
    int newSocket = acceptWrapper(fd, nullptr, nullptr);
    if (newSocket == invalidSocketId)
    {
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket:",
                         "accept",
                         "::accept() ", Utility::systemErrorMessage());
    }
    return newSocket;
}


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
IOResult ConnectionNormal::read(char* buffer, std::size_t size)
{
    IOInfo get = readWrapper(fd, buffer, size);
    Result r   = Result::OK;
    if (get.first == -1)
    {
        switch (get.second)
        {
#ifdef __WINNT__
            case WSANOTINITIALISED:
            case WSAEFAULT:
            case WSAENOTCONN:
            case WSAENOTSOCK:
            case WSAEOPNOTSUPP:
            case WSAEINVAL:
#endif
            case EBADF:
            case EFAULT:
            case EINVAL:
            case ENXIO:
            case ENOMEM:
            {
                r = Result::CriticalBug;
                break;
            }
#ifdef __WINNT__
            case WSAENETDOWN:
#endif
            case EIO:
            case ENOBUFS:
            {
                r = Result::ResourceFail;
                break;
            }
#ifdef __WINNT__
            case WSAEINTR:
#endif
            case EINTR:
            {
                r = Result::Interupt;
                break;
            }
#ifdef __WINNT__
            case WSAEINPROGRESS:
            case WSAEWOULDBLOCK:
            case WSAEMSGSIZE:
#endif
            case ETIMEDOUT:
            case EAGAIN:
            //case EWOULDBLOCK:
            {
                r = Result::Timeout;
                break;
            }
#ifdef __WINNT__
            case WSAENETRESET:
            case WSAESHUTDOWN:
            case WSAECONNABORTED:
            case WSAETIMEDOUT:
            case WSAECONNRESET:
#endif
            case ECONNRESET:
            case ENOTCONN:
            {
                r = Result::ConnectionClosed;
                break;
            }
            default:
            {
                r = Result::Unknown;
                break;
            }
        }
    }
    return {get.first, r};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOResult ConnectionNormal::write(char const* buffer, std::size_t size)
{
    IOInfo put  = writeWrapper(fd, buffer, size);
    Result r    = Result::OK;
    if (put.first == -1)
    {
        switch (put.second)
        {
#ifdef __WINNT__
            case WSANOTINITIALISED:
            case WSAEFAULT:
            case WSAENOTCONN:
            case WSAENOTSOCK:
            case WSAEOPNOTSUPP:
            case WSAEINVAL:
#endif
            case EINVAL:
            case EBADF:
            case ECONNRESET:
            case ENXIO:
            case EPIPE:
            {
                r = Result::CriticalBug;
                break;
            }
#ifdef __WINNT__
            case WSAENETDOWN:
#else
            case EDQUOT:
#endif
            case EFBIG:
            case EIO:
            case ENETDOWN:
            case ENETUNREACH:
            case ENOSPC:
            {
                r = Result::ResourceFail;
                break;
            }
#ifdef __WINNT__
            case WSAEINTR:
#endif
            case EINTR:
            {
                r = Result::Interupt;
                break;
            }
#ifdef __WINNT__
            case WSAEINPROGRESS:
            case WSAEWOULDBLOCK:
            case WSAEMSGSIZE:
#endif
            case ETIMEDOUT:
            case EAGAIN:
            //case EWOULDBLOCK:
            {
                r = Result::Timeout;
                break;
            }
#ifdef __WINNT__
            case WSAENETRESET:
            case WSAESHUTDOWN:
            case WSAECONNABORTED:
            case WSAETIMEDOUT:
            case WSAECONNRESET:
#endif
            case ENOTCONN:
            {
                r = Result::ConnectionClosed;
                break;
            }
            default:
            {
                r = Result::Unknown;
                break;
            }
        }
    }
    return {put.first, r};
}

std::string ConnectionNormal::errorMessage(ssize_t /*result*/)
{
    return Utility::systemErrorMessage();
}
