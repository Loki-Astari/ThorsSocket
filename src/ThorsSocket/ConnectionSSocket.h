#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_H

#include "ThorsSocketConfig.h"
#include "ConnectionSocket.h"

#include <openssl/ssl.h>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

extern "C" int certificateInfo_PasswdCB(char* buf, int size, int /*rwflag*/, void* userdata);

enum class SSLMethodType {Client, Server};
enum Protocol { TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3 };
class SSLctx;
class SSocket;
class SSLctxBuilder;

struct ProtocolInfo
{
    Protocol    minProtocol     = TLS_1_2;
    Protocol    maxProtocol     = TLS_1_3;

    void setProtocolInfo(SSL_CTX* ctx)   const;
    void setProtocolInfo(SSL* ssl)       const;
    private:
        int convertProtocolToOpenSSL(Protocol protocol) const;
};

struct CipherInfo
{
    std::string         cipherList          =   "ECDHE-ECDSA-AES128-GCM-SHA256"     ":"
                                                "ECDHE-RSA-AES128-GCM-SHA256"       ":"
                                                "ECDHE-ECDSA-AES256-GCM-SHA384"     ":"
                                                "ECDHE-RSA-AES256-GCM-SHA384"       ":"
                                                "ECDHE-ECDSA-CHACHA20-POLY1305"     ":"
                                                "ECDHE-RSA-CHACHA20-POLY1305"       ":"
                                                "DHE-RSA-AES128-GCM-SHA256"         ":"
                                                "DHE-RSA-AES256-GCM-SHA384";
    std::string         cipherSuite         =   "TLS_AES_256_GCM_SHA384"            ":"
                                                "TLS_CHACHA20_POLY1305_SHA256"      ":"
                                                "TLS_AES_128_GCM_SHA256";
    void setCipherInfo(SSL_CTX* ctx)    const;
    void setCipherInfo(SSL* ssl)        const;
};

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

enum AuthorityType { File, Dir, Store };

template<AuthorityType A>
struct CertifcateAuthorityDataInfo
{
    bool                        loadDefault = false;
    std::vector<std::string>    items;

    void setCertifcateAuthorityInfo(SSL_CTX* ctx)   const;
    int setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx) const;
    int setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const*) const;
    std::string type() const;
};

struct CertifcateAuthorityInfo
{
    CertifcateAuthorityDataInfo<File>   file;
    CertifcateAuthorityDataInfo<Dir>    dir;
    CertifcateAuthorityDataInfo<Store>  store;

    void setCertifcateAuthorityInfo(SSL_CTX* ctx)   const;
};

template<AuthorityType A>
struct ClientCAListDataInfo
{
    std::vector<std::string>        items;

    int addCAToList(STACK_OF(X509_NAME)* certs, char const* item) const;
};

struct ClientCAListInfo
{
    bool                                verifyClientCA = false;
    ClientCAListDataInfo<File>          file;
    ClientCAListDataInfo<Dir>           dir;
    ClientCAListDataInfo<Store>         store;

    STACK_OF(X509_NAME)* buildCAToList()            const;
    void setCertifcateAuthorityInfo(SSL_CTX* ctx)   const;
    void setCertifcateAuthorityInfo(SSL* ssl)       const;
};

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
