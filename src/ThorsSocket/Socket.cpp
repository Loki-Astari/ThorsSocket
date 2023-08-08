#include "Socket.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

namespace Utility = ThorsAnvil::Utility;

THORS_SOCKET_HEADER_ONLY_INCLUDE
BaseSocket::BaseSocket(std::unique_ptr<Connection>&& newConnection, bool blocking)
    : connection(std::move(newConnection))
{
    if (!isValid())
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                 "BaseSocket",
                                 "bad socket: ", Utility::systemErrorMessage());
    }
    if (!blocking)
    {
        connection->makeSocketNonBlocking();
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
BaseSocket::~BaseSocket()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool BaseSocket::isValid() const
{
    return connection.get() != nullptr && connection->isValid();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int BaseSocket::socketId() const
{
    return connection.get() == nullptr ? -1 : connection->socketId();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void BaseSocket::close()
{
    if (!isValid())
    {
        ThorsLogAndThrowLogical("ThorsAnvil::ThorsSocket::BaseSocket::",
                                "close",
                                "Called on a bad socket object (this object was moved)");
    }
    connection->close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void BaseSocket::swap(BaseSocket& other) noexcept
{
    using std::swap;
    swap(connection,   other.connection);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
BaseSocket::BaseSocket(BaseSocket&& move) noexcept
    : connection(nullptr)
{
    move.swap(*this);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
BaseSocket& BaseSocket::operator=(BaseSocket&& move) noexcept
{
    move.swap(*this);
    return *this;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
DataSocket::DataSocket(std::unique_ptr<Connection>&& connection, bool blocking)
    : BaseSocket(std::move(connection), blocking)
    , readYield([](){})
    , writeYield([](){})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void DataSocket::setYield(std::function<void()>&& yr, std::function<void()>&& yw)
{
    readYield = std::move(yr);
    writeYield= std::move(yw);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::pair<bool, std::size_t> DataSocket::getMessageData(char* buffer, std::size_t size, std::size_t alreadyGot)
{
    if (!isValid())
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::pair<bool, std::size_t> DataSocket::putMessageData(char const* buffer, std::size_t size, std::size_t alreadyPut)
{
    if (!isValid())
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
void DataSocket::putMessageClose()
{
    connection->shutdown();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectSocket::ConnectSocket(ConnectionBuilder const& builder, std::string const& host, int port)
    : DataSocket(builder(socketWrapper(PF_INET, SOCK_STREAM, 0)), true)
{
    connection->connect(host, port);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
ServerSocket::ServerSocket(int port, bool blocking, int maxWaitingConnections)
    : BaseSocket(std::make_unique<ConnectionNormal>(socketWrapper(PF_INET, SOCK_STREAM, 0)), blocking)
{
    connection->bind(port, maxWaitingConnections);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
DataSocket ServerSocket::accept(ConnectionBuilder const& builder, bool blocking)
{
    if (!isValid())
    {
        ThorsLogAndThrowLogical("ThorsAnvil::Socket::ServerSocket::",
                                "accept",
                                ": called on a bad socket object (this object was moved)");
    }

    int newSocket = connection->accept();
    std::unique_ptr<Connection> newConnection   = builder(newSocket);
    newConnection->acceptEstablishConnection();
    return DataSocket(std::move(newConnection), blocking);
}
