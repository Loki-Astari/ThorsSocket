#include "ConnectionSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>

#include <iostream>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

Socket::Socket(std::string const& host, int port, Blocking blocking)
    : fd(thorInvalidFD())
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    fd  = MOCK_FUNC(socket)(AF_INET, SOCK_STREAM, 0);
    if (fd == thorInvalidFD())
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
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

        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
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

        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
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

            ThorsLogAndThrowAction(
                ERROR,
                std::runtime_error,
                "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
                "Socket",
                " :Failed on ::thorSetSocketNonBlocking.",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
            );
        }
    }
}

Socket::Socket(SOCKET_TYPE fd)
    : fd(fd)
{}

Socket::~Socket()
{
    close();
}

bool Socket::isConnected() const
{
    return fd != thorInvalidFD();
}

int Socket::socketId(Mode /*rw*/) const
{
    return static_cast<int>(fd);
}

void Socket::close()
{
    if (fd != thorInvalidFD()) {
        MOCK_FUNC(thorCloseSocket)(fd);
    }
    fd = thorInvalidFD();
}

void Socket::tryFlushBuffer()
{
    int result = MOCK_FUNC(thorShutdownSocket)(fd);
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::Socket",
            "tryFlushBuffer",
            " :Win Failed on ::shutdown.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
}

#ifdef __WINNT__
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
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
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
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
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
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
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
                    " errno = ", saveErrno, " ", getErrNoStrWin(saveErrno),
                    " msg >", getErrMsgWin(saveErrno), "<"
                );
            }
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}

#else

int Socket::getReadFD() const
{
    return fd;
}

int Socket::getWriteFD() const
{
    return fd;
}

#endif
