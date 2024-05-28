#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionFileDescriptor.h"
#include "ConnectionWrapper.h"

#ifdef  __WINNT__
#else
#include <netdb.h>
#endif

#include <map>

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

        char const* getErrNoStr(int error)
        {
            static std::map<int, char const*> errorString =
            {
                {WSAEPROVIDERFAILEDINIT, "WSAEPROVIDERFAILEDINIT"}, {WSAEINPROGRESS, "WSAEINPROGRESS"}, {WSAEMFILE, "WSAEMFILE"},
                {WSAEINVALIDPROCTABLE, "WSAEINVALIDPROCTABLE"}, {WSAEAFNOSUPPORT, "WSAEAFNOSUPPORT"}, {WSAENOBUFS, "WSAENOBUFS"},
                {WSAEINVALIDPROVIDER, "WSAEINVALIDPROVIDER"}, {WSANOTINITIALISED, "WSANOTINITIALISED"}, {WSAENETDOWN, "WSAENETDOWN"},
                {WSAEPROTONOSUPPORT, "WSAEPROTONOSUPPORT"}, {WSAESOCKTNOSUPPORT, "WSAESOCKTNOSUPPORT"}, {WSAEPROTOTYPE, "WSAEPROTOTYPE"},
                {WSAHOST_NOT_FOUND, "WSAHOST_NOT_FOUND"}, {WSAEMSGSIZE, "WSAEMSGSIZE"}, {WSAEINVAL, "WSAEINVAL"},
                {WSAEADDRNOTAVAIL, "WSAEADDRNOTAVAIL"}, {WSATRY_AGAIN, "WSATRY_AGAIN"}, {WSAEACCES, "WSAEACCES"},
                {WSAECONNREFUSED, "WSAECONNREFUSED"}, {WSAETIMEDOUT, "WSAETIMEDOUT"}, {WSAEFAULT, "WSAEFAULT"},
                {WSAEHOSTUNREACH, "WSAEHOSTUNREACH"}, {WSAESHUTDOWN, "WSAESHUTDOWN"}, {WSANO_DATA, "WSANO_DATA"},
                {WSAECONNABORTED, "WSAECONNABORTED"}, {WSAENETRESET, "WSAENETRESET"}, {WSAEISCONN, "WSAEISCONN"},
                {WSANO_RECOVERY, "WSANO_RECOVERY"}, {WSAEOPNOTSUPP, "WSAEOPNOTSUPP"}, {WSAEALREADY, "WSAEALREADY"},
                {WSAENETUNREACH, "WSAENETUNREACH"}, {WSAEADDRINUSE, "WSAEADDRINUSE"}, {WSAENOTCONN, "WSAENOTCONN"},
                {WSAEWOULDBLOCK, "WSAEWOULDBLOCK"}, {WSAECONNRESET, "WSAECONNRESET"}, {WSAENOTSOCK, "WSAENOTSOCK"},
                {WSAEINTR, "WSAEINTR"},
            };
            auto find = errorString.find(error);
            char const* msg = (find == errorString.end()) ? "Unknown" : find->second;
            return msg;
        }
        char const* getErrMsg(int error)
        {
            static char msgbuf[1024];
            msgbuf[0] = '\0';
            FormatMessage(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,     // flags
                    NULL,                                                           // lpsource
                    error,                                                          // message id
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),                      // languageid
                    msgbuf,                                                         // output buffer
                    sizeof(msgbuf),                                                 // size of msgbuf, bytes
                    NULL                                                            // va_list of arguments
                    );
            return msgbuf;
        }
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
