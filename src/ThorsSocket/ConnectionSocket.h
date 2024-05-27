#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionFileDescriptor.h"
#include "ConnectionWrapper.h"

#ifdef  __WINNT__
#else
#include <netdb.h>
#endif

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

using SocketAddrIn  = struct ::sockaddr_in;
using SocketAddr    = struct ::sockaddr;
using HostEnt       = struct ::hostent;

#ifdef __WINNT__
class Socket: public Connection
{
    SOCKET fd;
    public:
        Socket(std::string const& host, int port, Blocking blocking);
        Socket(SOCKET fd);
        virtual ~Socket();

        virtual bool isConnected()                          const   override;
        virtual int  socketId(Mode rw)                      const   override;
        virtual void close()                                        override;
        virtual void tryFlushBuffer()                               override;

        virtual IOData readFromStream(char* buffer, std::size_t size)       override;
        virtual IOData writeToStream(char const* buffer, std::size_t size)  override;

        char const* getErrNoStr(int /*error*/)  {return "";}
        char const* getErrMsg(int /*error*/)    {return "";}

};
#else
class Socket: public ConnectionType::FileDescriptor
{
    int fd;
    public:
        Socket(std::string const& host, int port, Blocking blocking);
        Socket(int fd);
        virtual ~Socket();

        virtual bool isConnected()                          const   override;
        virtual int  socketId(Mode rw)                      const   override;
        virtual void close()                                        override;
        virtual void tryFlushBuffer()                               override;

        virtual int getReadFD()                             const   override;
        virtual int getWriteFD()                            const   override;
};
#endif

}

#endif
