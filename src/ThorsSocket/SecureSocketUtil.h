#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_CONFIG_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SECURE_SOCKET_CONFIG_H

#include "ThorsSocketConfig.h"
#include "ThorsLogging/ThorsLogging.h"

#include <string>
#include <utility>
#include <vector>
#include <functional>

#include <openssl/ssl.h>
#include <openssl/err.h>


namespace ThorsAnvil::ThorsSocket
{
    namespace ConnectionType
    {
        class SSocketBase;
        class SSocketStandard;
    }

extern "C" int certificateInfo_PasswdCB(char* buf, int size, int /*rwflag*/, void* userdata);
int certificateInfo_PasswdCBNormal(char* buf, int size, int rwflag, void* userdata);
std::string buildOpenSSLErrorMessage(bool prefix = true);

enum class  SSLMethodType   { Client, Server};
enum Protocol               { TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3};
enum AuthorityType          { File, Dir, Store};
enum SystemDefault          { Load};

using StringList    = std::vector<std::string>;

class SSLUtil
{
    SSLUtil();
    public:
        static SSLUtil& getInstance();

        SSLUtil(SSLUtil const&)                 = delete;
        SSLUtil& operator=(SSLUtil const&)      = delete;
};

/*
 * SSL manipulators
 *   Objects of these type can be passed to SSLctx constructor.
 *   These can be passed as const reference values and thus constructed inline if needed.
 *
 *      ProtocolInfo
 *      CipherInfo
 *      CertificateInfo
 *      CertifcateAuthorityFile
 *      CertifcateAuthorityDir
 *      CertifcateAuthorityStore
 *      ClientCAListInfo
 */

struct ProtocolInfo
{
    private:
        Protocol    minProtocol     = TLS_1_2;
        Protocol    maxProtocol     = TLS_1_3;

        int convertProtocolToOpenSSL(Protocol protocol) const;
    public:
        ProtocolInfo()
            : ProtocolInfo(TLS_1_2, TLS_1_3)
        {}
        ProtocolInfo(Protocol minProtocol, Protocol maxProtocol)
            : minProtocol(minProtocol)
            , maxProtocol(maxProtocol)
        {}

        void apply(SSL_CTX* ctx)   const;
        void apply(SSL* ssl)       const;
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
    void apply(SSL_CTX* ctx)    const;
    void apply(SSL* ssl)        const;
};

struct CertificateInfo
{
    public:
        using GetPasswordFunc = std::function<std::string(int)>;
    private:
        friend int ThorsAnvil::ThorsSocket::certificateInfo_PasswdCBNormal(char*, int, int, void*);

        std::string     certificateFileName;
        std::string     keyFileName;
        bool            hasPasswordGetter;
        GetPasswordFunc getPassword;

    public:
        CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName);
        CertificateInfo(std::string const& certificateFileName, std::string const& keyFileName, GetPasswordFunc&& getPassword);

        void apply(SSL_CTX* ctx)   const;
        void apply(SSL* ssl)       const;
};

template<AuthorityType A>
class CertifcateAuthorityDataInfo
{
    bool            loadDefault;
    StringList      items;

    int setDefaultCertifcateAuthorityInfo(SSL_CTX* ctx) const;
    int setOneCertifcateAuthorityInfo(SSL_CTX* ctx, char const*) const;
    std::string type() const;

    public:
        CertifcateAuthorityDataInfo(SystemDefault, StringList fileList = {})
            : loadDefault(true)
            , items(std::move(fileList))
        {}
        CertifcateAuthorityDataInfo(SystemDefault, std::string file)
            : loadDefault(true)
            , items({std::move(file)})
        {}
        CertifcateAuthorityDataInfo(StringList fileList)
            : loadDefault(false)
            , items(std::move(fileList))
        {}
        CertifcateAuthorityDataInfo(std::string file)
            : loadDefault(false)
            , items({std::move(file)})
        {}

        void apply(SSL_CTX* ctx)   const;
};

using CertifcateAuthorityFile   = CertifcateAuthorityDataInfo<File>;
using CertifcateAuthorityDir    = CertifcateAuthorityDataInfo<Dir>;
using CertifcateAuthorityStore  = CertifcateAuthorityDataInfo<Store>;

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
    void apply(SSL_CTX* ctx)   const;
    void apply(SSL* ssl)       const;
};
class SSLctx
{
    private:
        friend class ConnectionType::SSocketBase;
        friend class ConnectionType::SSocketStandard;
        SSL_CTX*            ctx;
    public:
        template<typename... Args>
        SSLctx(SSLMethodType methodType, Args&&... args);
               // ProtocolInfo
               // CipherInfo
               // CertificateInfo
               // CertifcateAuthorityInfo
               // ClientCAListInfo

        ~SSLctx();

        SSLctx(SSLctx const&)                   = delete;
        SSLctx& operator=(SSLctx const&)        = delete;

        SSLctx(SSLctx&& move)
            : ctx(std::exchange(move.ctx, nullptr))
        {}
        SSLctx& operator=(SSLctx&& move)
        {
            ctx = std::exchange(move.ctx, nullptr);
            return *this;
        }
    private:
        SSL_METHOD const*       createClient();
        SSL_METHOD const*       createServer();
        SSL_CTX*                newCtx(SSL_METHOD const* method);
};

template<typename... Args>
SSLctx::SSLctx(SSLMethodType methodType, Args&&... args)
    : ctx(nullptr)
{
    SSLUtil::getInstance();
    SSL_METHOD const*  method;
    if (methodType == SSLMethodType::Client) {
        method = createClient(); // SSLv23_client_method();
    }
    else {
        method = createServer();
    }

    if (method == nullptr)
    {
        ThorsLogAndThrowDebug(std::runtime_error,
                              "ThorsAnvil::THorsSocket::SSLctx",
                              "SSLctx",
                              "TLS_client_method() failed: ", buildOpenSSLErrorMessage());
    }

    ctx = newCtx(method);
    if (ctx == nullptr)
    {
        ThorsLogAndThrowDebug(std::runtime_error,
                              "ThorsAnvil::ThorsSocket::SSLctx",
                              "SSLctx",
                              "SSL_CTX_new() failed: ", buildOpenSSLErrorMessage());
    }

    (args.apply(ctx),...);
}


}

#if THORS_SOCKET_HEADER_ONLY
#include "SecureSocketUtil.source"
#endif

#endif
