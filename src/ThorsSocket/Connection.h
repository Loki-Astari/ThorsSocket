#ifndef THORS_ANVIL_DB_CONNECTION_H
#define THORS_ANVIL_DB_CONNECTION_H

#include <cstddef>
#include <string>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

using SocketAddr    = struct sockaddr;
using SocketStorage = struct sockaddr_storage;
using SocketAddrIn  = struct sockaddr_in;
using HostEnt       = struct hostent;

inline int closeWrapper(int fd)                                                     {return ::close(fd);}
inline int socketWrapper(int family, int type, int protocol)                        {return ::socket(family, type, protocol);}
inline int connectWrapper(int fd, SocketAddr* serverAddr, std::size_t sizeAddress)  {return ::connect(fd, serverAddr, sizeAddress);}
inline int acceptWrapper(int sockfd, sockaddr* addr, socklen_t* len)                {return ::accept(sockfd, addr, len);}
inline ssize_t readWrapper(int fd, void* buf, size_t count)                         {return ::read(fd, buf, count);}
inline ssize_t writeWrapper(int fd, void const* buf, size_t count)                  {return ::write(fd, buf, count);}
inline int shutdownWrapper(int fd, int how)                                         {return ::shutdown(fd, how);}
inline int fcntlWrapper(int fd, int cmd, int value)                                 {return ::fcntl(fd, cmd, value);}

namespace ThorsAnvil::ThorsIO
{

class Connection
{
    public:
        virtual ~Connection() {}
        virtual void accept();
        virtual void connect(int fd, std::string const& host, int port);
        virtual int read(int fd, char* buffer, std::size_t size);
        virtual int write(int fd, char const* buffer, std::size_t size);
};

}

#endif
