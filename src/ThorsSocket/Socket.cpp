#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

Socket SocketBuilder::build()
{
    return Socket(std::move(connection), std::move(readYield), std::move(writeYield));
}

Socket::Socket(std::unique_ptr<Connection>&& connectionP, std::function<void()>&& readYield, std::function<void()>&& writeYield)
    : connection(std::move(connectionP))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

Socket::Socket(Socket&& move) noexcept
    : connection(std::exchange(move.connection, nullptr))
    , readYield(std::exchange(move.readYield, [](){}))
    , writeYield(std::exchange(move.writeYield, [](){}))
{}

Socket& Socket::operator=(Socket&& move) noexcept
{
    connection.reset(nullptr);
    readYield = [](){};
    writeYield =[](){};
    swap(move);
    return *this;
}

void Socket::swap(Socket& other) noexcept
{
    using std::swap;
    swap(connection, other.connection);
    swap(readYield,  other.readYield);
    swap(writeYield, other.writeYield);
}

bool Socket::isConnected() const
{
    return connection.get() != nullptr && connection->isConnected();
}

int Socket::socketId(Mode rw) const
{
    if (!isConnected()) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "socketId", "Socket is in an invalid state");
    }
    return connection->socketId(rw);
}

IOData Socket::getMessageData(void* buffer, std::size_t size)
{
    if (!isConnected()) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "getMessageData", "Socket is in an invalid state");
    }

    std::size_t dataRead = 0;
    do
    {
        IOResult result = connection->read(static_cast<char*>(buffer), size, dataRead);
        dataRead = result.first;
        switch (result.second)
        {
            case Result::OK:
                break;
            case Result::CriticalBug:
                ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::Socket", "getMessageData", "CriticalBug: connection read failed", connection->errorMessage());
                break;
            case Result::Interupt:
                continue;
            case Result::ConnectionClosed:
                return {false, dataRead};
            case Result::WouldBlock:
                readYield();
                continue;
            case Result::Unknown:
                // fall through
            default:
                ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "getMessageData", "Unknown: connection read failed", connection->errorMessage());
        }
    }
    while (dataRead != size);
    return {true, dataRead};
}

IOData Socket::putMessageData(void const* buffer, std::size_t size)
{
    if (!isConnected()) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "putMessageData", "Socket is in an invalid state");
    }

    std::size_t dataWritten = 0;
    do
    {
        IOResult result = connection->write(static_cast<char const*>(buffer), size, dataWritten);
        dataWritten = result.first;
        switch (result.second)
        {
            case Result::OK:
                break;
            case Result::CriticalBug:
                ThorsLogAndThrowCritical("ThorsAnvil::ThorsSocket::Socket", "putMessageData", "CriticalBug: connection read failed", connection->errorMessage());
                break;
            case Result::Interupt:
                continue;
            case Result::ConnectionClosed:
                return {false, dataWritten};
            case Result::WouldBlock:
                writeYield();
                continue;
            case Result::Unknown:
                // fall through
            default:
                ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "getMessageData", "Unknown: connection read failed", connection->errorMessage());
        }
    }
    while (dataWritten != size);
    return {true, dataWritten};
}

void Socket::tryFlushBuffer()
{
    if (!isConnected()) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "tryFlushBuffer", "Socket is in an invalid state");
    }
    connection->tryFlushBuffer();
}

void Socket::close()
{
    if (!isConnected()) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::Socket", "close", "Socket is in an invalid state");
    }
    connection->close();
}

namespace ThorsAnvil::ThorsSocket
{
    void swap(Socket& lhs, Socket& rhs)
    {
        lhs.swap(rhs);
    }
}
