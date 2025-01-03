#include "ConnectionSocket.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStandard::SocketStandard(ServerInfo const& socketInfo, Blocking blocking)
    : fd(thorInvalidFD())
{
    createSocket();
    setUpServerSocket(socketInfo);
    setUpBlocking(blocking);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStandard::SocketStandard(SocketInfo const& socketInfo, Blocking blocking)
    : fd(thorInvalidFD())
{
    createSocket();
    setUpClientSocket(socketInfo);
    setUpBlocking(blocking);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStandard::SocketStandard(OpenSocketInfo const& socketInfo, Blocking blocking)
    : fd(socketInfo.fd)
{
    setUpBlocking(blocking);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::createSocket()
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    fd  = MOCK_FUNC(socket)(AF_INET, SOCK_STREAM, 0);
    if (fd == thorInvalidFD())
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
            "createSocket",
            " :Failed on ::socket.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::setUpBlocking(Blocking blocking)
{
    if (blocking == Blocking::No)
    {
        if (MOCK_FUNC(thorSetSocketNonBlocking)(fd) == -1)
        {
            int saveErrno = thorGetSocketError();
            MOCK_FUNC(thorCloseSocket)(fd);

            ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
                "setUpBlocking",
                " :Failed on ::thorSetSocketNonBlocking",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
            );
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::setUpServerSocket(ServerInfo const& socketInfo)
{
    SocketAddrIn        serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(socketInfo.port);
    serverAddr.sin_addr.s_addr  = INADDR_ANY;
    int status = ::bind(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr));
    if (status == -1)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
                "setUpServerSocket",
                " :Failed on ::bind",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
                );
    }

    status = ::listen(fd, 5);
    if (status == -1)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
                "setUpServerSocket",
                " :Failed on ::listen",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
                );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::setUpClientSocket(SocketInfo const& socketInfo)
{
    HostEnt* serv = nullptr;
    do
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-gethostbyname
        serv = MOCK_FUNC(gethostbyname)(&socketInfo.host[0]);
    }
    while (serv == nullptr && thorErrorIsTryAgain(thorGetSocketError()));

    if (serv == nullptr)
    {
        int saveErrno = thorGetSocketError();
        MOCK_FUNC(thorCloseSocket)(fd);

        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
            "setUpClientSocket",
            " :Failed on ::gethostbyname.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }

    SocketAddrIn serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(socketInfo.port);
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
            "ThorsAnvil::ThorsSocket::ConnectionType::SocketStandard",
            "setUpClientSocket",
            " :Failed on ::connect.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketStandard::~SocketStandard()
{
    close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SocketStandard::isConnected() const
{
    return fd != thorInvalidFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketStandard::socketId(Mode /*rw*/) const
{
    return static_cast<int>(fd);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::close()
{
    if (fd != thorInvalidFD()) {
        MOCK_FUNC(thorCloseSocket)(fd);
    }
    fd = thorInvalidFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketStandard::release()
{
    fd = thorInvalidFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketStandard::getFD() const
{
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketClient::SocketClient(SocketInfo const& socketInfo, Blocking blocking)
    : socketInfo(socketInfo, blocking)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketClient::SocketClient(SocketServer&, OpenSocketInfo const& socketInfo, Blocking blocking)
    : socketInfo(socketInfo, blocking)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketClient::~SocketClient()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SocketClient::isConnected() const
{
    return socketInfo.isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketClient::socketId(Mode rw) const
{
    return socketInfo.socketId(rw);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketClient::close()
{
    return socketInfo.close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketClient::release()
{
    return socketInfo.release();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketClient::tryFlushBuffer()
{
    int result = MOCK_FUNC(thorShutdownSocket)(socketInfo.getFD());
    if (result != 0)
    {
        int saveErrno = thorGetSocketError();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SocketClient",
            "tryFlushBuffer",
            " :Win Failed on ::shutdown.",
            " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
            " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
}

#ifdef __WINNT__
THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SocketClient::readFromStream(char* buffer, std::size_t size)
{
    int chunkRead = MOCK_FUNC(recv)(socketInfo.getFD(), buffer, size, 0);
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
                    "ThorsAnvil::ThorsSocket::ConnectionType::SocketClient",
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
                    "ThorsAnvil::ThorsSocket::ConnectionType::SocketClient",
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
IOData SocketClient::writeToStream(char const* buffer, std::size_t size)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-send
    int chunkWritten = MOCK_FUNC(send)(socketInfo.getFD(), buffer, size, 0);
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
                    "ThorsAnvil::ThorsSocket::ConnectionType::SocketClient",
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
                    "ThorsAnvil::ThorsSocket::ConnectionType::SocketClient",
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
int SocketClient::getReadFD() const
{
    return socketInfo.getFD();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketClient::getWriteFD() const
{
    return socketInfo.getFD();
}

#endif

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketServer::SocketServer(ServerInfo&& socketInfo, Blocking blocking)
    : socketInfo(socketInfo, blocking)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SocketServer::~SocketServer()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SocketServer::isConnected() const
{
    return socketInfo.isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketServer::socketId(Mode rw) const
{
    return socketInfo.socketId(rw);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketServer::close()
{
    return socketInfo.close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketServer::release()
{
    return socketInfo.release();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SocketServer::waitForFileDescriptor(int fd)
{
    int result;
    using PollFD = THOR_POLL_TYPE;
    PollFD  fds[1] = {{THOR_SOCKET_ID(fd), static_cast<short>(POLLIN | THOR_POLLPRI), 0}};

    while ((result = THOR_POLL(fds, 1, -1)) <= 0)
    {
        if (result == THOR_POLL_ERROR) {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SocketServer", "waitForInput", ": poll return an error");
        }
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SocketServer::wouldBlock(int errorCode)
{
#ifdef __WINNT__
    return errorCode == WSAEWOULDBLOCK;
#else
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
    return (errorCode == EAGAIN || errorCode == EWOULDBLOCK);
#else
    return (errorCode == EAGAIN);
#endif
#endif
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SocketServer::acceptSocket(YieldFunc& yield)
{
    using SocketStorage = sockaddr_storage;
    using SocketLen     = socklen_t;

    SocketStorage   serverStorage;
    SocketLen       addr_size   = sizeof serverStorage;

    SOCKET_TYPE acceptedFd = thorInvalidFD();
    while (acceptedFd == thorInvalidFD())
    {
        acceptedFd = ::accept(socketInfo.getFD(), reinterpret_cast<SocketAddr*>(&serverStorage), &addr_size);
        if (acceptedFd != thorInvalidFD()) {
            break;
        }
        int saveErrno = thorGetSocketError();
        if (wouldBlock(saveErrno))
        {
            if (!yield()) {
                waitForFileDescriptor(socketInfo.getFD());
            }
            continue;
        }

        ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::SocketServer",
                "accept",
                " :Failed on ::accept.",
                " errno = ", saveErrno, " ", getErrNoStrSocket(saveErrno),
                " msg >", getErrMsgSocket(saveErrno), "<"
        );
    }
    return acceptedFd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::unique_ptr<ThorsAnvil::ThorsSocket::ConnectionClient> SocketServer::accept(YieldFunc& yield, Blocking blocking, DeferAccept)
{
    return std::make_unique<SocketClient>(*this, OpenSocketInfo{static_cast<SOCKET_TYPE>(acceptSocket(yield))}, blocking);
}
