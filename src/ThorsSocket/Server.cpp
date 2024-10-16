#include "Server.h"
#include "ConnectionSocket.h"
#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"

using namespace ThorsAnvil::ThorsSocket;

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(ServerInfo const& socketInfo, Blocking blocking, YieldFunc&& readYield, YieldFunc&& writeYield)
    : connection(std::make_unique<ConnectionType::SocketServer>(socketInfo, blocking))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(SServerInfo const& ssocketInfo, Blocking blocking, YieldFunc&& readYield, YieldFunc&& writeYield)
    : connection(std::make_unique<ConnectionType::SSocketServer>(ssocketInfo, blocking))
    , readYield(std::move(readYield))
    , writeYield(std::move(writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::Server(Server&& move) noexcept
    : connection(std::move(move.connection))
    , readYield(std::move(move.readYield))
    , writeYield(std::move(move.writeYield))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server::~Server()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
Server& Server::operator=(Server&& move) noexcept
{
    connection.reset(nullptr);
    readYield = [](){return false;};
    writeYield =[](){return false;};
    swap(move);
    return *this;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void Server::swap(Server& other) noexcept
{
    using std::swap;
    swap(connection, other.connection);
    swap(readYield,  other.readYield);
    swap(writeYield, other.writeYield);
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
Socket Server::accept(Blocking blocking, AcceptFunc&& accept, YieldFunc&& readYield, YieldFunc&& writeYield)
{
    std::unique_ptr<ConnectionClient>   data = connection->accept(blocking, std::move(accept));
    return Socket(std::move(data), std::move(readYield), std::move(writeYield));
}
