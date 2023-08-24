#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionSocket.h"

#include <openssl/ssl.h>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class SSLUtil
{
    SSLUtil();
    public:
        static SSLUtil& getInstance();

        SSLUtil(SSLUtil const&)                 = delete;
        SSLUtil& operator=(SSLUtil const&)      = delete;
};

enum class SSLMethodType {Client, Server};
class SSLctx;
class SSocket;
class SSLctxClient;
class SSLctxServer;

class SSLctx
{
    friend class SSocket;
    protected:
        SSL_CTX*            ctx;
        SSLctx(SSLMethodType method = SSLMethodType::Client);
    public:
        ~SSLctx();

        SSLctx(SSLctx const&)                   = delete;
        SSLctx& operator=(SSLctx const&)        = delete;
};

class SSLctxClient: public SSLctx
{
    public:
        SSLctxClient();
};

class SSLctxServer: public SSLctx
{
    public:
        SSLctxServer();
};

class SSocket: public Socket
{
    SSL*        ssl;
    public:
        SSocket(SSLctx const& ctx, std::string const& host, int port, Blocking blocking);
        SSocket(int fd, SSLctx const& ctx);
        virtual ~SSocket();
        virtual void tryFlushBuffer()                               override;

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)             override;
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)   override;

        virtual std::string errorMessage(ssize_t)                   override;
        virtual void close()                                        override;
        virtual bool isConnected()                          const   override;

        static std::string buildErrorMessage(bool prefix = true);
        static std::string buildErrorMessage(int code);
};

}

#endif
