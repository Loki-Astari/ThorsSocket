#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionSocket.h"

#include <cstddef>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class SSocket;

class SSocketStandard
{
    SSL*        ssl;
    public:
        SSocketStandard(SServerInfo const& socketInfo, int fd);
        SSocketStandard(SSocketInfo const& socketInfo, int fd);
        SSocketStandard(OpenSSocketInfo const& socketInfo, int fd);
        ~SSocketStandard();
        IOData writeToStream(char const* buffer, std::size_t size);

        bool isConnected() const;
        void close();

        char const* getSSErrNoStr(int);

        SSL* getSSL() const;
    private:
        void initSSocket(SSLctx const& ctx, CertificateInfo&& info, int fd);
        void initSSocketServer();
        void initSSocketClient();
};

class SSocketClient: public SocketClient
{
    SSocketStandard     secureSocketInfo;
    public:
        SSocketClient(SSocketInfo const& socketInfo, Blocking blocking);
        SSocketClient(OpenSSocketInfo const& socketInfo);
        virtual ~SSocketClient();

        virtual bool isConnected() const override;
        virtual void close()             override;

        void           tryFlushBuffer()                                     override;
        virtual IOData readFromStream(char* buffer, std::size_t size)       override;
        virtual IOData writeToStream(char const* buffer, std::size_t size)  override;
};

class SSocketServer: public SocketServer
{
    SSocketStandard     secureSocketInfo;
    public:
        SSocketServer(SServerInfo const& socketInfo, Blocking blocking);
        virtual ~SSocketServer();

        virtual bool isConnected()                          const   override;
        virtual void close()                                        override;

        virtual std::unique_ptr<ConnectionClient> accept(Blocking blocking)          override;
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "ConnectionSSocket.source"
#endif

#endif
