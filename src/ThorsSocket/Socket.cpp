#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

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
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "socketId", "Socket is in an invalid state");
    }
    return connection->socketId(rw);
}

IOData Socket::getMessageData(void* b, std::size_t size)
{
    char* buffer = reinterpret_cast<char*>(b);

    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "getMessageData", "Socket is in an invalid state");
    }

    std::size_t dataRead = 0;
    while (dataRead != size)
    {
        IOData chunk = connection->readFromStream(buffer + dataRead, size - dataRead);
        dataRead += chunk.dataSize;
        if (!chunk.stillOpen) {
            return {dataRead, false, false};
        }
        if (chunk.blocked) {
            readYield();
        }
    }
    return {dataRead, true, false};
}

IOData Socket::putMessageData(void const* b, std::size_t size)
{
    char const* buffer = reinterpret_cast<char const*>(b);

    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "putMessageData", "Socket is in an invalid state");
    }

    std::size_t dataWritten = 0;
    while (dataWritten != size)
    {
        IOData chunk = connection->writeToStream(buffer + dataWritten, size - dataWritten);
        dataWritten += chunk.dataSize;
        if (!chunk.stillOpen) {
            return {dataWritten, false, false};
        }
        if (chunk.blocked) {
            writeYield();
        }
    }
    return {dataWritten, true, false};
}

void Socket::tryFlushBuffer()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "tryFlushBuffer", "Socket is in an invalid state");
    }
    connection->tryFlushBuffer();
}

void Socket::close()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "close", "Socket is in an invalid state");
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
