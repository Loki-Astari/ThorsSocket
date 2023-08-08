#include "Socket.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

namespace Utility = ThorsAnvil::Utility;

BaseSocket::BaseSocket()
    : socketId(invalidSocketId)
{}

BaseSocket::BaseSocket(int socketId, bool blocking)
    : socketId(socketId)
{
    if (socketId == invalidSocketId)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                 "BaseSocket",
                                 "bad socket: ", Utility::systemErrorMessage());
    }
    if (!blocking)
    {
        makeSocketNonBlocking();
    }
}

void BaseSocket::makeSocketNonBlocking()
{
    if (::nonBlockingWrapper(socketId) == -1)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                 "makeSocketNonBlocking",
                                 "::fcntl() ", Utility::systemErrorMessage());
    }
}

BaseSocket::~BaseSocket()
{
    if (socketId == invalidSocketId)
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

void BaseSocket::close()
{
    if (socketId == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                "close",
                                "Called on a bad socket object (this object was moved)");
    }
    while (true)
    {
        if (::closeWrapper(socketId) == -1)
        {
            switch (errno)
            {
                case EBADF: socketId = invalidSocketId;
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                                     "close"
                                                     "::close() ", socketId, " ", Utility::systemErrorMessage());
                case EIO:   socketId = invalidSocketId;
                            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::BaseSocket::",
                                             "close",
                                             "::close() ", socketId, " ", Utility::systemErrorMessage());
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
                default:    socketId = invalidSocketId;
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                                     "close",
                                                     "::close() ", socketId, " ", Utility::systemErrorMessage());
            }
        }
        break;
    }
    socketId = invalidSocketId;
}

void BaseSocket::swap(BaseSocket& other) noexcept
{
    using std::swap;
    swap(socketId,   other.socketId);
}

BaseSocket::BaseSocket(BaseSocket&& move) noexcept
    : socketId(invalidSocketId)
{
    move.swap(*this);
}

BaseSocket& BaseSocket::operator=(BaseSocket&& move) noexcept
{
    move.swap(*this);
    return *this;
}

DataSocket::DataSocket(ConnectionBuilder const& builder, int socketId, bool blocking, bool server)
    : BaseSocket(socketId, blocking)
    , readYield([](){})
    , writeYield([](){})
    , connection(builder(socketId))
{
    if (server)
    {
        connection->accept();
    }
}

void DataSocket::setYield(std::function<void()>&& yr, std::function<void()>&& yw)
{
    readYield = std::move(yr);
    writeYield= std::move(yw);
}

std::pair<bool, std::size_t> DataSocket::getMessageData(char* buffer, std::size_t size, std::size_t alreadyGot)
{
    if (getSocketId() == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::ThorsSocket::DataSocket::",
                                "getMessageData",
                                "called on a bad socket object (this object was moved)");
    }

    std::size_t     dataRead  = alreadyGot;
    while (dataRead < size)
    {
        // The inner loop handles interactions with the socket.
        IOInfo get = connection->read(buffer + dataRead, size - dataRead);
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
                    // Fatal error. Programming bug
                    ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::DataSocket::",
                                             "getMessageData",
                                             "::read() critical error: ", Utility::systemErrorMessage());
                }
#ifdef __WINNT__
                case WSAENETDOWN:
#endif
                case EIO:
                case ENOBUFS:
                {
                   // Resource acquisition failure or device error
                    ThorsLogAndThrow("ThorsAnvil::ThorsSocket::DataSocket::",
                                     "getMessageData",
                                     "::read(): resource failure: ", Utility::systemErrorMessage());
                }
#ifdef __WINNT__
                case WSAEINTR:
#endif
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
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
                    // Temporary error.
                    // Simply retry the read.
                    readYield();
                    return {true, dataRead - alreadyGot};
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
                    // Connection broken.
                    // Return the data we have available and exit
                    // as if the connection was closed correctly.
                    return {false, dataRead - alreadyGot};
                }
                default:
                {
                    ThorsLogAndThrow("ThorsAnvil::ThorsSocket::DataSocket::",
                                     "getMessageData",
                                     "::read() returned -1: ", Utility::systemErrorMessage());
                }
            }
        }
        if (get.first == 0)
        {
            return {false, dataRead - alreadyGot};
        }
        dataRead += get.first;
    }

    return {true, dataRead - alreadyGot};
}

std::pair<bool, std::size_t> DataSocket::putMessageData(char const* buffer, std::size_t size, std::size_t alreadyPut)
{
    if (getSocketId() == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::Socket::DataSocket::",
                                "putMessageData",
                                "called on a bad socket object (this object was moved)");
    }

    std::size_t     dataWritten = alreadyPut;

    while (dataWritten < size)
    {
        IOInfo put = connection->write(buffer + dataWritten, size - dataWritten);
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
                    // Fatal error. Programming bug
                    ThorsLogAndThrowCritical("ThorsAnvil::Socket::DataSocket::",
                                             "putMessageData",
                                             "::write() critical error: ", Utility::systemErrorMessage());
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
                    // Resource acquisition failure or device error
                    ThorsLogAndThrow("ThorsAnvil::Socket::DataSocket::",
                                     "putMessageData",
                                     "::write() resource failure: ", Utility::systemErrorMessage());
                }
#ifdef __WINNT__
                case WSAEINTR:
#endif
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
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
                    // Temporary error.
                    // Simply retry the read.
                    writeYield();
                    return {true, dataWritten - alreadyPut};
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
                    // Connection broken.
                    // Return the data we have available and exit
                    // as if the connection was closed correctly.
                    return {false, dataWritten - alreadyPut};
                }
                default:
                {
                    ThorsLogAndThrow("ThorsAnvil::Socket::DataSocket::",
                                     "putMessageData",
                                     "::write() returned -1: ", Utility::systemErrorMessage());
                }
            }
        }
        dataWritten += put.first;
    }
    return {true, dataWritten - alreadyPut};
}

#ifdef  __WINNT__
#define THOR_SHUTDOWN_WRITE     SD_SEND
#else
#define THOR_SHUTDOWN_WRITE     SHUT_WR
#endif
void DataSocket::putMessageClose()
{
    if (::shutdown(getSocketId(), THOR_SHUTDOWN_WRITE) != 0)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::Socket::DataSocket::",
                                 "putMessageClose",
                                 "::shutdown(): critical error: ", Utility::systemErrorMessage());
    }
}

ConnectSocket::ConnectSocket(ConnectionBuilder const& builder, std::string const& host, int port)
    : DataSocket(builder, ::socketWrapper(PF_INET, SOCK_STREAM, 0), true, false)
{
    connection->connect(host, port);
}

ServerSocket::ServerSocket(int port, bool blocking, int maxWaitingConnections)
    : BaseSocket(::socketWrapper(PF_INET, SOCK_STREAM, 0), blocking)
{
    SocketAddrIn    serverAddr = {};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    serverAddr.sin_addr.s_addr  = INADDR_ANY;

    if (bindWrapper(getSocketId(), reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::bind() ", Utility::systemErrorMessage());
    }

    if (listnWrapper(getSocketId(), maxWaitingConnections) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::listen() ", Utility::systemErrorMessage());
    }
}

DataSocket ServerSocket::accept(ConnectionBuilder const& builder, bool blocking)
{
    if (getSocketId() == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::Socket::ServerSocket::",
                                "accept",
                                ": called on a bad socket object (this object was moved)");
    }

    int newSocket = ::acceptWrapper(getSocketId(), nullptr, nullptr);
    if (newSocket == invalidSocketId)
    {
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket:",
                         "accept",
                         "::accept() ", Utility::systemErrorMessage());
    }
    return DataSocket(builder, newSocket, blocking, true);
}
