#include "Server.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(ServerInfo const& socketInfo, Blocking blocking)
    : connection(std::make_unique<ConnectionType::SocketServer>(socketInfo, blocking))
    , yield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(SServerInfo const& ssocketInfo, Blocking blocking)
    : connection(std::make_unique<ConnectionType::SSocketServer>(ssocketInfo, blocking))
    , yield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(Server&& move) noexcept
    : connection(std::move(move.connection))
    , yield([](){return false;})
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::~Server()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server& Server::operator=(Server&& move) noexcept
{
    connection.reset(nullptr);
    yield = [](){return false;};
    swap(move);
    return *this;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Server::swap(Server& other) noexcept
{
    using std::swap;
    swap(connection, other.connection);
    swap(yield,      other.yield);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool Server::isConnected() const
{
    return connection.get() != nullptr && connection->isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int Server::socketId(Mode rw) const
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsServer::Server", "socketId", "Server is in an invalid state");
    }
    return connection->socketId(rw);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Server::close()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsServer::Server", "close", "Server is in an invalid state");
    }
    connection->close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Server::release()
{
    if (!isConnected()) {
        ThorsLogAndThrow("ThorsAnvil::ThorsServer::Server", "close", "Server is in an invalid state");
    }
    connection->release();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Socket Server::accept(Blocking blocking)
{
    std::unique_ptr<ConnectionClient>   data = connection->accept(yield, blocking);
    return Socket(std::move(data));
}
