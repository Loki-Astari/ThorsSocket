#include "Socket.h"
#include "ConnectionSimpleFile.h"
#include "ConnectionPipe.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

struct SocketConnectionBuilder
{
    Blocking blocking;
    SocketConnectionBuilder(Blocking blocking)
        : blocking(blocking)
    {}
    std::unique_ptr<ConnectionClient> operator()(FileInfo const& fileInfo)      {return std::make_unique<ConnectionType::SimpleFile>(fileInfo, blocking);}
    std::unique_ptr<ConnectionClient> operator()(PipeInfo const& pipeInfo)      {return std::make_unique<ConnectionType::Pipe>(pipeInfo, blocking);}
    std::unique_ptr<ConnectionClient> operator()(SocketInfo const& socketInfo)  {return std::make_unique<ConnectionType::SocketClient>(socketInfo, blocking);}
    std::unique_ptr<ConnectionClient> operator()(SSocketInfo const& ssocketInfo){return std::make_unique<ConnectionType::SSocketClient>(ssocketInfo, blocking);}
};

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket()
    : connection(nullptr)
    , readYield([](){return false;})
    , writeYield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(std::unique_ptr<ConnectionClient>&& connection)
    : connection(std::move(connection))
    , readYield([](){return false;})
    , writeYield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(SocketInit const& initInfo, Blocking blocking)
    : connection(std::visit(SocketConnectionBuilder{blocking}, initInfo))
    , readYield([](){return false;})
    , writeYield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::Socket(Socket&& move) noexcept
    : connection(std::exchange(move.connection, nullptr))
    , readYield(std::exchange(move.readYield, [](){return false;}))
    , writeYield(std::exchange(move.writeYield, [](){return false;}))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket::~Socket()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket& Socket::operator=(Socket&& move) noexcept
{
    connection.reset(nullptr);
    readYield = [](){return false;};
    writeYield =[](){return false;};
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
    return getMessageDataFromStream(b, size, true);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData Socket::tryGetMessageData(void* b, std::size_t size)
{
    return getMessageDataFromStream(b, size, false);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData Socket::getMessageDataFromStream(void* b, std::size_t size, bool waitWhenBlocking)
{
    char* buffer = reinterpret_cast<char*>(b);

    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "getMessageDataFromStream", "Socket is in an invalid state");
    }

    std::size_t dataRead = 0;
    while (dataRead != size)
    {
        IOData chunk = connection->readFromStream(buffer + dataRead, size - dataRead);
        dataRead += chunk.dataSize;
        if (!chunk.stillOpen) {
            return {dataRead, false, false};
        }
        if (chunk.blocked)
        {
            if (!waitWhenBlocking) {
                return {dataRead, true, true};
            }
            if (!readYield()) {
                waitForInput();
            }
        }
    }
    return {dataRead, true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData Socket::putMessageData(void const* b, std::size_t size)
{
    return putMessageDataToStream(b, size, true);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData Socket::tryPutMessageData(void const* b, std::size_t size)
{
    return putMessageDataToStream(b, size, false);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData Socket::putMessageDataToStream(void const* b, std::size_t size, bool waitWhenBlocking)
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
        if (chunk.blocked)
        {
            if (!waitWhenBlocking) {
                return {dataWritten, true, true};
            }

            if (!writeYield()) {
                waitForOutput();
            }
        }
    }
    return {dataWritten, true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::waitForInput()
{
    waitForFileDescriptor(socketId(Mode::Read), POLLIN);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::waitForOutput()
{
    waitForFileDescriptor(socketId(Mode::Write), POLLOUT);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::waitForFileDescriptor(int fd, short flag)
{
    int result;
    using PollFD = THOR_POLL_TYPE;
    PollFD  fds[1] = {{THOR_SOCKET_ID(fd), static_cast<short>(flag | THOR_POLLPRI), 0}};

    while ((result = THOR_POLL(fds, 1, -1)) <= 0)
    {
        if (result == THOR_POLL_ERROR) {
            ThorsLogAndThrow("ThorsAnvil::ThorsSocket::Socket", "waitForInput", ": poll return an error");
        }
    }
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


THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::externalyClosed()
{
    if (connection.get() != nullptr) {
        connection->externalyClosed();
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Socket::deferInit()
{
    if (connection.get() != nullptr) {
        connection->deferInit(readYield, writeYield);
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::string_view Socket::protocol()
{
    return connection->protocol();
}
