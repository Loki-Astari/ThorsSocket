#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionSocket.h"

#include <openssl/ssl.h>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

extern "C" int certificateInfo_PasswdCB(char* buf, int size, int /*rwflag*/, void* userdata);

struct CertificateInfo
{
    public:
        using GetPasswordFunc = std::function<std::string(int)>;
    private:
        friend int certificateInfo_PasswdCB(char*, int, int, void*);

        std::string     certificateFileName;
        std::string     keyFileName;
        GetPasswordFunc getPassword;

    public:
        CertificateInfo();
        CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName, GetPasswordFunc&& getPassword = [](int){return "";});

        void setCertificateInfo(SSL_CTX* ctx);
        void setCertificateInfo(SSL* ssl);
};

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
        SSLctxClient(CertificateInfo&& info = CertificateInfo{});
};

class SSLctxServer: public SSLctx
{
    public:
        SSLctxServer(CertificateInfo&& info = CertificateInfo{});
};

class SSocket: public Socket
{
    SSL*        ssl;
    public:
        SSocket(SSLctx const& ctx, std::string const& host, int port, Blocking blocking, CertificateInfo&& info = CertificateInfo{});
        SSocket(int fd, SSLctx const& ctx, CertificateInfo&& info = CertificateInfo{});
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
