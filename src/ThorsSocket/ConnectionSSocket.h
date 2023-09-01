#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionSSocketUtil.h"
#include "ConnectionSocket.h"

#include <openssl/ssl.h>


namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class SSocket;
class SSLctxBuilder;

class SSLUtil
{
    SSLUtil();
    public:
        static SSLUtil& getInstance();

        SSLUtil(SSLUtil const&)                 = delete;
        SSLUtil& operator=(SSLUtil const&)      = delete;
};

class SSLctx
{
    friend class SSocket;
    friend class SSLctxBuilder;
    private:
        SSL_CTX*            ctx;
        SSLctx(SSLMethodType methodType,
               ProtocolInfo protocol,
               CipherInfo const& cipherList,
               CertificateInfo const& certificateInfo,
               CertifcateAuthorityInfo const& certifcateAuthority,
               ClientCAListInfo const& clinetCAList);

    public:
        ~SSLctx();

        SSLctx(SSLctx const&)                   = delete;
        SSLctx& operator=(SSLctx const&)        = delete;
};

class SSLctxBuilder
{
    SSLMethodType           method;
    ProtocolInfo            protocolRange;
    CipherInfo              cipherList;
    CertificateInfo         certificate;
    CertifcateAuthorityInfo certifcateAuthority;
    ClientCAListInfo        clientCAList;

    public:
        SSLctxBuilder(SSLMethodType method): method(method)                 {}
        SSLctxBuilder& setProtocolInfo(ProtocolInfo info)                   {protocolRange = std::move(info);return *this;}
        SSLctxBuilder& setCipherInfo(CipherInfo&& info)                     {cipherList = std::move(info);return *this;}
        SSLctxBuilder& addCertificateInfo(CertificateInfo&& info)           {certificate = std::move(info);return *this;}
        SSLctxBuilder& addDefaultCertifcateAuthorityFile()                  {certifcateAuthority.file.loadDefault = true;return *this;}
        SSLctxBuilder& addDefaultCertifcateAuthorityDir()                   {certifcateAuthority.dir.loadDefault = true;return *this;}
        SSLctxBuilder& addDefaultCertifcateAuthorityStore()                 {certifcateAuthority.store.loadDefault = true;return *this;}
        SSLctxBuilder& addCertifcateAuthorityFile(std::string const& file)  {certifcateAuthority.file.items.push_back(file);return *this;}
        SSLctxBuilder& addCertifcateAuthorityDir(std::string const& dir)    {certifcateAuthority.dir.items.push_back(dir);return *this;}
        SSLctxBuilder& addCertifcateAuthorityStore(std::string const& store){certifcateAuthority.store.items.push_back(store);return *this;}
        SSLctxBuilder& validateClientCA()                                   {clientCAList.verifyClientCA = true;return *this;}
        SSLctxBuilder& addFileToClientCAList(std::string const& file)       {clientCAList.file.items.push_back(file);return *this;}
        SSLctxBuilder& addDirToClientCAList(std::string const& dir)         {clientCAList.dir.items.push_back(dir);return *this;}
        SSLctxBuilder& addStoreToClientCAList(std::string const& store)     {clientCAList.store.items.push_back(store);return *this;}

        SSLctx  build()
        {
            return SSLctx{method, protocolRange, cipherList, certificate, certifcateAuthority, clientCAList};
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
