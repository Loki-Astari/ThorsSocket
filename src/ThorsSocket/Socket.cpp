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
        IOResult get = connection->read(buffer + dataRead, size - dataRead);
        switch (get.second)
        {
            case Result::OK:
                break;
            case Result::CriticalBug:
                {
                    // Fatal error. Programming bug
                    ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::DataSocket::",
                                             "getMessageData",
                                             "::read() critical error: ", connection->errorMessage(get.first));
                }
            case Result::ResourceFail:
                {
                   // Resource acquisition failure or device error
                    ThorsLogAndThrow("ThorsAnvil::ThorsSocket::DataSocket::",
                                     "getMessageData",
                                     "::read(): resource failure: ", connection->errorMessage(get.first));
                }
            case Result::Interupt:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
            case Result::Timeout:
                {
                    // Temporary error.
                    // Simply retry the read.
                    readYield();
                    return {true, dataRead - alreadyGot};
                }
            case Result::ConnectionClosed:
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
                                     "::read() returned -1: ", connection->errorMessage(get.first));
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
        IOResult put = connection->write(buffer + dataWritten, size - dataWritten);
        switch (put.second)
        {
            case Result::OK:
                break;
            case Result::CriticalBug:
                {
                    // Fatal error. Programming bug
                    ThorsLogAndThrowCritical("ThorsAnvil::Socket::DataSocket::",
                                             "putMessageData",
                                             "::write() critical error: ", connection->errorMessage(put.first));
                }
            case Result::ResourceFail:
                {
                    // Resource acquisition failure or device error
                    ThorsLogAndThrow("ThorsAnvil::Socket::DataSocket::",
                                     "putMessageData",
                                     "::write() resource failure: ", connection->errorMessage(put.first));
                }
            case Result::Interupt:
                {
                    // TODO: Check for user interrupt flags.
                    //       Beyond the scope of this project
                    //       so continue normal operations.
                    continue;
                }
            case Result::Timeout:
                {
                    // Temporary error.
                    // Simply retry the read.
                    writeYield();
                    return {true, dataWritten - alreadyPut};
                }
            case Result::ConnectionClosed:
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
                                     "::write() returned -1: ", connection->errorMessage(put.first));
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
