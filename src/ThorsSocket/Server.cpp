#include "Server.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"
#include <iostream>

using namespace ThorsAnvil::ThorsSocket;

struct ServerConnectionBuilder
{
    Blocking blocking;
    ServerConnectionBuilder(Blocking blocking)
        : blocking(blocking)
    {}
    std::unique_ptr<ConnectionServer> operator()(ServerInfo&& socketInfo)      {return std::make_unique<ConnectionType::SocketServer>(std::move(socketInfo), blocking);}
    std::unique_ptr<ConnectionServer> operator()(SServerInfo&& ssocketInfo)    {return std::make_unique<ConnectionType::SSocketServer>(std::move(ssocketInfo), blocking);}
};

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(ServerInit&& initInfo, Blocking blocking)
    : connection(std::visit(ServerConnectionBuilder{blocking}, std::move(initInfo)))
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
Socket Server::accept(Blocking blocking, DeferAccept deferAccept)
{
    std::unique_ptr<ConnectionClient>   data = connection->accept(yield, blocking, deferAccept);
    return Socket(std::move(data));
}
