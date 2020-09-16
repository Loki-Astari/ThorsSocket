#ifndef THORS_ANVIL_DB_COMMON_SSL_UTIL_H
#define THORS_ANVIL_DB_COMMON_SSL_UTIL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>


namespace ThorsAnvil::ThorsIO
{

class SSLUtil
{
    SSLUtil();
    public:
        static SSLUtil& getInstance();
        static std::string errorMessage();
        static std::string sslError(SSL* ssl, int ret);

        SSLUtil(SSLUtil const&)                 = delete;
        SSLUtil& operator=(SSLUtil const&)      = delete;
};

enum class SSLMethodType {Client, Server};
class SSLctx;
class SSLObj;
class SSLMethod
{
    friend class SSLctx;
    const SSL_METHOD* method;
    public:
        SSLMethod(SSLMethodType type);

        SSLMethod(SSLMethod const&)             = delete;
        SSLMethod& operator=(SSLMethod const&)  = delete;
};


class SSLctx
{
    friend class SSLObj;
    SSL_CTX*            ctx;
    public:
        SSLctx(SSLMethod& method);
        SSLctx(SSLMethod& method, std::string const& certFile, std::string const& keyFile);
        ~SSLctx();

        SSLctx(SSLctx const&)                   = delete;
        SSLctx& operator=(SSLctx const&)        = delete;
};

class SSLObj
{
    SSL*                ssl;
    public:
        SSLObj(SSLctx const& ctx, int fileDescriptor);
        ~SSLObj();

        SSLObj(SSLObj const&)                   = delete;
        SSLObj& operator=(SSLObj const&)        = delete;

        void accept();
        void connect();
        int read(char* buffer, std::size_t len);
        int write(char const* buffer, std::size_t len);
        int errorCode(int ret);
};


}

#endif
