#include "ConnectionSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <iostream>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

#ifdef __WINNT__
Socket::Socket(std::string const& host, int port, Blocking blocking)
    : fd(INVALID_SOCKET)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    fd  = MOCK_FUNC(socket)(AF_INET, SOCK_STREAM, 0);
    if (fd == INVALID_SOCKET)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Win Failed on ::socket.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", getErrMsg(saveErrno), "<"
        );
    }

    hostent*  serv = nullptr;
    do
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-gethostbyname
        serv = MOCK_FUNC(gethostbyname)(host.c_str());
    }
    while (serv == nullptr && thorGetSocketError() == WSATRY_AGAIN);
    if (serv == nullptr)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Win Failed on ::gethostbyname.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", getErrMsg(saveErrno), "<"
        );
    }

    SocketAddrIn serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    //serverAddr.sin_addr.s_addr  = inet_addr(reinterpret_cast<char*>(serv->h_addr));
    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
    int result = MOCK_FUNC(connect)(fd, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr));
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Win Failed on ::connect.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", getErrMsg(saveErrno), "<"
        );
    }

    if (blocking == Blocking::No)
    {
        if (MOCK_FUNC(thorSetSocketNonBlocking)(fd) == -1)
        {
            int saveErrno = thorGetSocketError();
            MOCK_FUNC(thorCloseSocket)(fd);

            ThorsLogAndThrowAction(
                ERROR,
                std::runtime_error,
                "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                "Socket",
                " :Win Failed on ::thorSetSocketNonBlocking.",
                " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                " msg >", getErrMsg(saveErrno), "<"
            );
        }
    }
}

Socket::Socket(SOCKET fd)
    : fd(fd)
{}

Socket::~Socket()
{
    close();
}

bool Socket::isConnected() const
{
    return fd != INVALID_SOCKET;
}

int Socket::socketId(Mode /*rw*/) const
{
    return static_cast<int>(fd);
}

void Socket::close()
{
    if (fd != INVALID_SOCKET) {
        MOCK_FUNC(thorCloseSocket)(fd);
    }
    fd = INVALID_SOCKET;
}

void Socket::tryFlushBuffer()
{
    int result = MOCK_FUNC(shutdown)(fd, SD_SEND);
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "tryFlushBuffer",
            " :Win Failed on ::shutdown.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", getErrMsg(saveErrno), "<"
        );
    }
}

IOData Socket::readFromStream(char* buffer, std::size_t size)
{
    int chunkRead = MOCK_FUNC(recv)(fd, buffer, size, 0);
    if (chunkRead == 0) {
        return {0, false, false};
    }
    if (chunkRead == SOCKET_ERROR)
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
        int saveErrno = thorGetSocketError();
        switch (saveErrno)
        {
            case WSAENETRESET:      [[fallthrough]];
            case WSAESHUTDOWN:      [[fallthrough]];
            case WSAECONNABORTED:   [[fallthrough]];
            case WSAETIMEDOUT:      [[fallthrough]];
            case WSAECONNRESET:     return {0, false, false};
            case WSAEWOULDBLOCK:    return {0, true, true};
            case WSAEINTR:          [[fallthrough]];
            case WSAEINPROGRESS:    return {0, true, false};
            case WSANOTINITIALISED: [[fallthrough]];
            case WSAENETDOWN:       [[fallthrough]];
            case WSAEFAULT:         [[fallthrough]];
            case WSAENOTCONN:       [[fallthrough]];
            case WSAENOTSOCK:       [[fallthrough]];
            case WSAEOPNOTSUPP:     [[fallthrough]];
            case WSAEINVAL:
            {
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketCritical,
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "readFromStream",
                    " :Win Failed on ::recv with SocketCritical",
                    " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                    " msg >", getErrMsg(saveErrno), "<"
                );
            }
            case WSAEMSGSIZE:       [[fallthrough]];
            default:
            {
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketUnknown,
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "readFromStream",
                    " :Win Failed on ::recv with SocketUnknown",
                    " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                    " msg >", getErrMsg(saveErrno), "<"
                );
            }
        }
    }
    return {static_cast<std::size_t>(chunkRead), true, false};
}

IOData Socket::writeToStream(char const* buffer, std::size_t size)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
    int chunkWritten = MOCK_FUNC(send)(fd, buffer, size, 0);
    if (chunkWritten == SOCKET_ERROR)
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
        int saveErrno = thorGetSocketError();
        switch (saveErrno)
        {
            case WSAENETRESET:      [[fallthrough]];
            case WSAESHUTDOWN:      [[fallthrough]];
            case WSAECONNABORTED:   [[fallthrough]];
            case WSAECONNRESET:     [[fallthrough]];
            case WSAETIMEDOUT:      return {0, false, false};
            case WSAEWOULDBLOCK:    return {0, true, true};
            case WSAEINTR:          [[fallthrough]];
            case WSAEINPROGRESS:    return {0, true, false};
            case WSANOTINITIALISED: [[fallthrough]];
            case WSAENETDOWN:       [[fallthrough]];
            case WSAEFAULT:         [[fallthrough]];
            case WSAENOBUFS:        [[fallthrough]];
            case WSAENOTCONN:       [[fallthrough]];
            case WSAENOTSOCK:       [[fallthrough]];
            case WSAEOPNOTSUPP:     [[fallthrough]];
            case WSAEHOSTUNREACH:   [[fallthrough]];
            case WSAEINVAL:
            {
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketCritical,
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "writeToStream",
                    " :Win Failed on ::send with SocketCritical",
                    " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                    " msg >", getErrMsg(saveErrno), "<"
                );
            }
            case WSAEACCES:         [[fallthrough]];
            case WSAEMSGSIZE:       [[fallthrough]];
            default:
            {
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketUnknown,
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "writeToStream",
                    " :Win Failed on ::send with SocketUnknown",
                    " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                    " msg >", getErrMsg(saveErrno), "<"
                );
            }
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}

#else
Socket::Socket(std::string const& hostname, int port, Blocking blocking)
    : fd(-1)
{
    fd = MOCK_FUNC(socket)(PF_INET, SOCK_STREAM, 0);
    int saveErrno = thorGetSocketError();
    if (fd == -1)
    {
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::socket.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", strerror(saveErrno), "<"
        );
    }


    HostEnt* serv = nullptr;
    do
    {
        serv = MOCK_FUNC(gethostbyname)(hostname.c_str());
    }
    while (serv == nullptr && h_errno == TRY_AGAIN);

    if (serv == nullptr)
    {
        int saveErrno = thorGetSocketError();

        MOCK_FUNC(thorCloseSocket)(fd);
        fd = -1;
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::gethostbyname.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", strerror(saveErrno), "<"
        );
    }

    SocketAddrIn serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    if (MOCK_FUNC(connect)(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);
        fd = -1;
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::connect.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", strerror(saveErrno), "<"
        );
    }

    if (blocking == Blocking::No)
    {
        if (MOCK_FUNC(thorSetSocketNonBlocking)(fd) == -1)
        {
            int saveErrno = thorGetSocketError();
            MOCK_FUNC(thorCloseSocket)(fd);
            fd = -1;
            ThorsLogAndThrowAction(
                ERROR,
                std::runtime_error,
                "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                "Socket",
                " :Failed on ::fcntl.",
                " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
                " msg >", strerror(saveErrno), "<"
            );
        }
    }
}


Socket::Socket(int fd)
    : fd(fd)
{}

Socket::~Socket()
{
    close();
}

bool Socket::isConnected() const
{
    return fd != -1;
}

int Socket::socketId(Mode) const
{
    // read and write use same file descriptor
    return fd;
}

void Socket::close()
{
    if (fd != -1) {
        MOCK_FUNC(thorCloseSocket)(fd);
    }
    fd = -1;
}

void Socket::tryFlushBuffer()
{
    if (MOCK_FUNC(shutdown)(fd, SHUT_WR) != 0)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::shutdown.",
            " errno = ", saveErrno, " ", getErrNoStr(saveErrno),
            " msg >", strerror(saveErrno), "<"
        );
    }
}

int Socket::getReadFD() const
{
    return fd;
}

int Socket::getWriteFD() const
{
    return fd;
}
#endif
