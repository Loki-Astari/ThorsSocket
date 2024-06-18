#include "Socket.h"
#include "Connection.h"
#include "ConnectionSimpleFile.h"
#include "ConnectionPipe.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <utility>
#include <algorithm>

using namespace ThorsAnvil::ThorsSocket;

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(FileInfo const& fileInfo, std::function<void()>&& readYield, std::function<void()>&& writeYield)
    : connection(std::make_unique<ConnectionType::SimpleFile>(fileInfo))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(PipeInfo const& pipeInfo, std::function<void()>&& readYield, std::function<void()>&& writeYield)
    : connection(std::make_unique<ConnectionType::Pipe>(pipeInfo))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(SocketInfo const& socketInfo, std::function<void()>&& readYield, std::function<void()>&& writeYield)
    : connection(std::make_unique<ConnectionType::Socket>(socketInfo))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(SSocketInfo const& ssocketInfo, std::function<void()>&& readYield, std::function<void()>&& writeYield)
    : connection(std::make_unique<ConnectionType::SSocketClient>(ssocketInfo))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(Socket&& move) noexcept
    : connection(std::exchange(move.connection, nullptr))
    , readYield(std::exchange(move.readYield, [](){}))
    , writeYield(std::exchange(move.writeYield, [](){}))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket& Socket::operator=(Socket&& move) noexcept
{
    connection.reset(nullptr);
    readYield = [](){};
    writeYield =[](){};
    swap(move);
    return *this;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::swap(Socket& other) noexcept
{
    using std::swap;
    swap(connection, other.connection);
    swap(readYield,  other.readYield);
    swap(writeYield, other.writeYield);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool Socket::isConnected() const
{
    return connection.get() != nullptr && connection->isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int Socket::socketId(Mode rw) const
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "socketId", "Socket is in an invalid state");
    }
    return connection->socketId(rw);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
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

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::tryFlushBuffer()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "tryFlushBuffer", "Socket is in an invalid state");
    }
    connection->tryFlushBuffer();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::close()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "close", "Socket is in an invalid state");
    }
    connection->close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::release()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "close", "Socket is in an invalid state");
    }
    connection->release();
}
