#include "ConnectionSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <iostream>
#include <algorithm>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(std::string const& host, int port, Blocking blocking)
    : fd(thorInvalidFD())
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    fd  = MOCK_FUNC(socket)(AF_INET, SOCK_STREAM, 0);
    if (fd == thorInvalidFD())
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::socket.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }

    HostEnt* serv = nullptr;
    do
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-gethostbyname
        serv = MOCK_FUNC(gethostbyname)(host.c_str());
    }
    while (serv == nullptr && thorErrorIsTryAgain(thorGetSocketError()));

    if (serv == nullptr)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::gethostbyname.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }

    SocketAddrIn serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
    int result = MOCK_FUNC(connect)(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr));
    //int result = MOCK_FUNC(connect)(fd, reinterpret_cast<SOCKADDR*>(&serverAddr), sizeof(serverAddr));
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "Socket",
            " :Failed on ::connect.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }

    if (blocking == Blocking::No)
    {
        if (MOCK_FUNC(thorSetSocketNonBlocking)(fd) == -1)
        {
            int saveErrno = thorGetSocketError();
            MOCK_FUNC(thorCloseSocket)(fd);

            ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                "Socket",
                " :Failed on ::thorSetSocketNonBlocking.",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
            );
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(SOCKET_TYPE fd)
    : fd(fd)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::~Socket()
{
    close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool Socket::isConnected() const
{
    return fd != thorInvalidFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int Socket::socketId(Mode /*rw*/) const
{
    return static_cast<int>(fd);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::close()
{
    if (fd != thorInvalidFD()) {
        MOCK_FUNC(thorCloseSocket)(fd);
    }
    fd = thorInvalidFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::tryFlushBuffer()
{
    int result = MOCK_FUNC(thorShutdownSocket)(fd);
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "tryFlushBuffer",
            " :Win Failed on ::shutdown.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
}

#ifdef __WINNT__
THORS_SOCKET_HEADER_ONLY_INCLUDE
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
            case WSAENETDOWN:       [[fallthrough]];
            case WSAECONNRESET:     return {0, false, false};
            case WSAEWOULDBLOCK:    return {0, true, true};
            case WSAEINTR:          [[fallthrough]];
            case WSAEINPROGRESS:    return {0, true, false};
            case WSANOTINITIALISED: [[fallthrough]];
            case WSAEFAULT:         [[fallthrough]];
            case WSAENOTCONN:       [[fallthrough]];
            case WSAENOTSOCK:       [[fallthrough]];
            case WSAEOPNOTSUPP:     [[fallthrough]];
            case WSAEINVAL:
            {
                ThorsLogAndThrowCritical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "readFromStream",
                    " :Win Failed on ::recv with SocketCritical",
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
                );
            }
            case WSAEMSGSIZE:       [[fallthrough]];
            default:
            {
                ThorsLogAndThrowLogical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "readFromStream",
                    " :Win Failed on ::recv with SocketUnknown",
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
                );
            }
        }
    }
    return {static_cast<std::size_t>(chunkRead), true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
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
            case WSAENETDOWN:       [[fallthrough]];
            case WSAETIMEDOUT:      return {0, false, false};
            case WSAEWOULDBLOCK:    return {0, true, true};
            case WSAEINTR:          [[fallthrough]];
            case WSAEINPROGRESS:    return {0, true, false};
            case WSANOTINITIALISED: [[fallthrough]];
            case WSAEFAULT:         [[fallthrough]];
            case WSAENOBUFS:        [[fallthrough]];
            case WSAENOTCONN:       [[fallthrough]];
            case WSAENOTSOCK:       [[fallthrough]];
            case WSAEOPNOTSUPP:     [[fallthrough]];
            case WSAEHOSTUNREACH:   [[fallthrough]];
            case WSAEINVAL:
            {
                ThorsLogAndThrowCritical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "writeToStream",
                    " :Win Failed on ::send with SocketCritical",
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
                );
            }
            case WSAEACCES:         [[fallthrough]];
            case WSAEMSGSIZE:       [[fallthrough]];
            default:
            {
                ThorsLogAndThrowLogical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                    "writeToStream",
                    " :Win Failed on ::send with SocketUnknown",
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
                );
            }
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}

#else

THORS_SOCKET_HEADER_ONLY_INCLUDE
int Socket::getReadFD() const
{
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int Socket::getWriteFD() const
{
    return fd;
}

#endif
