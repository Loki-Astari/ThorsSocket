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

        void setCertificateInfo(SSL_CTX* ctx)   const;
        void setCertificateInfo(SSL* ssl)       const;
};

struct CipherList
{
    std::string         cipherList          =   "ECDHE-ECDSA-AES128-GCM-SHA256"     ":"
                                                "ECDHE-RSA-AES128-GCM-SHA256"       ":"
                                                "ECDHE-ECDSA-AES256-GCM-SHA384"     ":"
                                                "ECDHE-RSA-AES256-GCM-SHA384"       ":"
                                                "ECDHE-ECDSA-CHACHA20-POLY1305"     ":"
                                                "ECDHE-RSA-CHACHA20-POLY1305"       ":"
                                                "DHE-RSA-AES128-GCM-SHA256"         ":"
                                                "DHE-RSA-AES256-GCM-SHA384";
    void setCipherList(SSL_CTX* ctx)    const;
    void setCipherList(SSL* ssl)        const;
};

struct CAInfo
{
    std::string     file;
    std::string     dir;

    void setCertifcateAuthority(SSL_CTX* ctx)   const;
    void setCertifcateAuthority(SSL* ssl)       const;
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
enum Protocol { TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3 };
class SSLctx;
class SSocket;
class SSLctxBuilder;

class SSLctx
{
    friend class SSocket;
    friend class SSLctxBuilder;
    private:
        SSL_CTX*            ctx;
        SSLctx(SSLMethodType methodType,
               Protocol protocolMin, Protocol protocolMax,
               CipherList const& cipherList,
               CertificateInfo const& certificateInfo,
               CAInfo const& caInfo);
    public:
        ~SSLctx();

        SSLctx(SSLctx const&)                   = delete;
        SSLctx& operator=(SSLctx const&)        = delete;
};

class SSLctxBuilder
{
    SSLMethodType       method;
    Protocol            protocolMin         = TLS_1_2;
    Protocol            protocolMax         = TLS_1_3;
    CipherList          cipherList;
    CertificateInfo     certificateInfo;
    CAInfo              caInfo;

    public:
        SSLctxBuilder(SSLMethodType method): method(method)         {}
        SSLctxBuilder& setProtocolMin(Protocol min)                 {protocolMin = min;return *this;}
        SSLctxBuilder& setProtocolMax(Protocol max)                 {protocolMax = max;return *this;}
        SSLctxBuilder& setCipherList(CipherList&& list)             {cipherList = std::move(list);return *this;}
        SSLctxBuilder& addCertificateInfo(CertificateInfo&& info)   {certificateInfo = std::move(info);return *this;}
        SSLctxBuilder& setTrustedCA(CAInfo&& info)                  {caInfo = std::move(info);return *this;}

        SSLctx  build()
        {
            return SSLctx{method, protocolMin, protocolMax, cipherList, certificateInfo, caInfo};
        }
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
