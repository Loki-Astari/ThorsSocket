#include "Socket.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"
#include <stdexcept>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <iostream>

using namespace ThorsAnvil::ThorsIO;

namespace Utility = ThorsAnvil::Utility;

BaseSocket::BaseSocket()
    : socketId(invalidSocketId)
{}

BaseSocket::BaseSocket(int socketId, bool blocking)
    : socketId(socketId)
{
    if (socketId == invalidSocketId)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::BaseSocket::",
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
    if (::fcntlWrapper(socketId, F_SETFL, O_NONBLOCK) == -1)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::BaseSocket::",
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
        ThorsCatchMessage("ThorsAnvil::ThorsIO::BaseSocket", "~BaseSocket", e.what());
    }
    catch (...)
    {
        ThorsCatchMessage("ThorsAnvil::ThorsIO::BaseSocket", "~BaseSocket", "UNKNOWN");
    }
}

void BaseSocket::close()
{
    if (socketId == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::ThorsIO::BaseSocket::",
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
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::BaseSocket::",
                                                     "close"
                                                     "::close() ", socketId, " ", Utility::systemErrorMessage());
                case EIO:   socketId = invalidSocketId;
                            ThorsLogAndThrow("ThorsAnvil::ThorsIO::BaseSocket::",
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
                            ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::BaseSocket::",
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

DataSocket::DataSocket(int socketId, bool blocking, bool server, ConnectionBuilder const& builder)
    : BaseSocket(socketId, blocking)
    , connection(builder(socketId))
{
    if (server)
    {
        connection->accept();
    }
}

std::pair<bool, std::size_t> DataSocket::getMessageData(char* buffer, std::size_t size, std::size_t alreadyGot)
{
    if (getSocketId() == invalidSocketId)
    {
        ThorsLogAndThrowLogical("ThorsAnvil::ThorsIO::DataSocket::",
                                "getMessageData",
                                "called on a bad socket object (this object was moved)");
    }

    std::size_t     dataRead  = alreadyGot;
    while (dataRead < size)
    {
        // The inner loop handles interactions with the socket.
        std::size_t get = connection->read(getSocketId(), buffer + dataRead, size - dataRead);
        if (get == static_cast<std::size_t>(-1))
        {
            switch (errno)
            {
                case EBADF:
                case EFAULT:
                case EINVAL:
                case ENXIO:
                case ENOMEM:
                {
                    // Fatal error. Programming bug
                    ThorsLogAndThrowCritical("ThorsAnvil::ThorsIO::DataSocket::",
                                             "getMessageData",
                                             "::read() critical error: ", Utility::systemErrorMessage());
                }
                case EIO:
                case ENOBUFS:
                {
                   // Resource acquisition failure or device error
                    ThorsLogAndThrow("ThorsAnvil::ThorsIO::DataSocket::",
                                     "getMessageData",
                                     "::read(): resource failure: ", Utility::systemErrorMessage());
                }
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
                case ETIMEDOUT:
                case EAGAIN:
                //case EWOULDBLOCK:
                {
                    // Temporary error.
                    // Simply retry the read.
                    return {true, dataRead - alreadyGot};
                }
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
                    ThorsLogAndThrow("ThorsAnvil::ThorsIO::DataSocket::",
                                     "getMessageData",
                                     "::read() returned -1: ", Utility::systemErrorMessage());
                }
            }
        }
        if (get == 0)
        {
            return {false, dataRead - alreadyGot};
        }
        dataRead += get;
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
        std::size_t put = connection->write(getSocketId(), buffer + dataWritten, size - dataWritten);
        if (put == static_cast<std::size_t>(-1))
        {
            switch (errno)
            {
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
                case EDQUOT:
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
                case EINTR:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
                case ETIMEDOUT:
                case EAGAIN:
                //case EWOULDBLOCK:
                {
                    // Temporary error.
                    // Simply retry the read.
                    return {true, dataWritten - alreadyPut};
                }
                default:
                {
                    ThorsLogAndThrow("ThorsAnvil::Socket::DataSocket::",
                                     "putMessageData",
                                     "::write() returned -1: ", Utility::systemErrorMessage());
                }
            }
        }
        dataWritten += put;
    }
    return {true, dataWritten - alreadyPut};
}

void DataSocket::putMessageClose()
{
    if (::shutdown(getSocketId(), SHUT_WR) != 0)
    {
        ThorsLogAndThrowCritical("ThorsAnvil::Socket::DataSocket::",
                                 "putMessageClose",
                                 "::shutdown(): critical error: ", Utility::systemErrorMessage());
    }
}

ConnectSocket::ConnectSocket(std::string const& host, int port, ConnectionBuilder const& builder)
    : DataSocket(::socketWrapper(PF_INET, SOCK_STREAM, 0), true, false, builder)
{
    connection->connect(getSocketId(), host, port);
}

ServerSocket::ServerSocket(int port, bool blocking, int maxWaitingConnections)
    : BaseSocket(::socketWrapper(PF_INET, SOCK_STREAM, 0), blocking)
{
    SocketAddrIn    serverAddr = {};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);
    serverAddr.sin_addr.s_addr  = INADDR_ANY;

    if (::bind(getSocketId(), reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::bind() ", Utility::systemErrorMessage());
    }

    if (::listen(getSocketId(), maxWaitingConnections) != 0)
    {
        close();
        ThorsLogAndThrow("ThorsAnvil::Socket::ServerSocket::",
                         "ServerSocket",
                         "::listen() ", Utility::systemErrorMessage());
    }
}

DataSocket ServerSocket::accept(bool blocking, ConnectionBuilder const& builder)
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
    return DataSocket(newSocket, blocking, true, builder);
}
