#include "ConnectionSocket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>

#include <iostream>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

Socket::Socket(std::string const& hostname, int port, Blocking blocking)
    : fd(-1)
{
    fd = MOCK_FUNC(socket)(PF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Socket", "Socket: ::open() failed. ", buildErrorMessage());
    }


    SocketAddrIn serverAddr{};
    serverAddr.sin_family       = AF_INET;
    serverAddr.sin_port         = htons(port);

    HostEnt* serv = nullptr;
    while (true)
    {
        serv = MOCK_FUNC(gethostbyname)(hostname.c_str());
        if (serv == nullptr && h_errno == TRY_AGAIN) {
            continue;
        }

        if (serv != nullptr) {
            break;
        }

        MOCK_FUNC(close)(fd);
        fd = -1;
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Socket", "Socket: ::gethostbyname() failed. ", buildErrorMessage());
    }

    char* src = reinterpret_cast<char*>(serv->h_addr);
    char* dst = reinterpret_cast<char*>(&serverAddr.sin_addr.s_addr);
    std::copy(src, src + serv->h_length, dst);

    if (MOCK_FUNC(connect)(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
    {
        MOCK_FUNC(close)(fd);
        fd = -1;
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Socket", "Socket: ::connect() failed. ", buildErrorMessage());
    }

    if (blocking == Blocking::No)
    {
        if (MOCK_TFUNC(fcntl)(fd, F_SETFL, O_NONBLOCK) == -1)
        {
            MOCK_FUNC(close)(fd);
            fd = -1;
            ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Socket", "Socket: ::fcntl() failed. ", buildErrorMessage());
        }
    }
}


Socket::Socket(int fd)
    : fd(fd)
{}

Socket::~Socket()
{
    if (isConnected()) {
        close();
    }
}

bool Socket::isConnected() const
{
    return fd != -1;
}

int Socket::socketId() const
{
    return fd;
}

void Socket::close()
{
    MOCK_FUNC(close)(fd);
    fd = -1;
}

void Socket::tryFlushBuffer()
{
    if (MOCK_FUNC(shutdown)(fd, SHUT_WR) != 0) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Socket", "tryFlushBuffer: ::shutdown() failed. ", buildErrorMessage());
    }
}

int Socket::getReadFD() const
{
    return fd;
}

int Socket::getWriteFD() const
{
    return fd;
}
