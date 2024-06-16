#include "ConnectionSSocket.h"

#include <map>
#include <iostream>
#include <openssl/err.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSL_METHOD const* SSLctx::createClient()            {return MOCK_FUNC(TLS_client_method)();}
THORS_SOCKET_HEADER_ONLY_INCLUDE
SSL_METHOD const* SSLctx::createServer()            {return MOCK_FUNC(TLS_server_method)();}
THORS_SOCKET_HEADER_ONLY_INCLUDE
SSL_CTX* SSLctx::newCtx(SSL_METHOD const* method)   {return MOCK_FUNC(SSL_CTX_new)(method);}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLUtil::SSLUtil()
{
    SSL_load_error_strings();
    SSL_library_init();
    //OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLUtil& SSLUtil::getInstance()
{
    static SSLUtil  instance;
    return instance;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLctx::~SSLctx()
{
    if (ctx) {
        MOCK_FUNC(SSL_CTX_free)(ctx);
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocket::SSocket(SSLctx const& ctx, std::string const& host, int port, Blocking blocking, CertificateInfo&& info)
    : Socket(host, port, blocking)
    , ssl(nullptr)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        int saveErrno = ERR_get_error();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
            "SSocket",
            " :Failed on SSL_new.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    info.apply(ssl);

    int ret;
    int error;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, socketId(Mode::Read))) != 1)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
            "SSocket",
            " :Failed on SSL_set_fd.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    do
    {
        ret = MOCK_FUNC(SSL_connect)(ssl);
        if (ret != 1)
        {
            // If you open a non blocking connection.
            // It may take a while to get all the information you need
            // If you are simply waiting then you have to keep going.
            //
            // TODO: Opportunity for yield()?
            error = MOCK_FUNC(SSL_get_error)(ssl, ret);
            if (error == SSL_ERROR_WANT_CONNECT || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        break;
    }
    while (true);

    if (ret != 1)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
            "SSocket",
            " :Failed on SSL_connect.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }


    X509* cert = MOCK_FUNC(SSL_get1_peer_certificate)(ssl);
    if (cert == nullptr)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
            "SSocket",
            " :Failed on SSL_get1_peer_certificate.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }
    MOCK_FUNC(X509_free)(cert);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocket::SSocket(int fd, SSLctx const& ctx, CertificateInfo&& info)
    : Socket(fd)
{
    /*Create new ssl object*/
    ssl = SSL_new(ctx.ctx);
    if (ssl == nullptr)
    {
        int saveErrno = ERR_get_error();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
            "SSocket",
            " :Failed on SSL_new.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    info.apply(ssl);

    /* Bind the ssl object with the socket*/
    SSL_set_fd(ssl, fd);
}

SSocketServer::SSocketServer(int fd, SSLctx const& ctx, CertificateInfo&& info)
    : SSocket(fd, ctx, std::move(info))
{
    /*Do the SSL Handshake*/
    int status;
    do
    {
        status = SSL_accept(ssl);
        if (status != 1)
        {
            int error = MOCK_FUNC(SSL_get_error)(ssl, status);
            if (error == SSL_ERROR_WANT_ACCEPT || error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
                continue;
            }
        }
        break;
    }
    while (true);

    /* Check for error in handshake*/
    if (status < 1)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, status);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketServer",
            "SSocketServer",
            " :Failed on SSL_accept.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    /* Check for Client authentication error */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketServer",
            "SSocketServer",
            " :Failed on SSL_get_verify_result."
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocket::~SSocket()
{
    close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocket::tryFlushBuffer()
{
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocket::readFromStream(char* buffer, std::size_t size)
{
    int ret = MOCK_FUNC(SSL_read)(ssl, buffer, size);
    if (ret <= 0)
    {
        int errorCode = MOCK_FUNC(SSL_get_error)(ssl, ret);
        switch (errorCode)
        {
            case SSL_ERROR_NONE:                return {0, true, false};
            case SSL_ERROR_ZERO_RETURN:         return {0, false,false};
            case SSL_ERROR_WANT_READ:           return {0, true, true};
            case SSL_ERROR_WANT_WRITE:          [[fallthrough]];
            case SSL_ERROR_WANT_CONNECT:        [[fallthrough]];
            case SSL_ERROR_WANT_ACCEPT:         [[fallthrough]];
            case SSL_ERROR_SYSCALL:             [[fallthrough]];
            case SSL_ERROR_SSL:
            {
                    ThorsLogAndThrowCritical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                        " readFromStream",
                        " :SocketCritical exception thrown.",
                        " errno = ", errorCode, " ", getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
                    );
            }
            case SSL_ERROR_WANT_X509_LOOKUP:    [[fallthrough]];
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:[[fallthrough]];
            case SSL_ERROR_WANT_ASYNC:          [[fallthrough]];
            case SSL_ERROR_WANT_ASYNC_JOB:      [[fallthrough]];
            default:
            {
                    ThorsLogAndThrowLogical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                        " readFromStream",
                        " :UnknownCritical exception thrown.",
                        " errno = ", errorCode, " ", getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
                    );
            }
        }
    }
    return {static_cast<std::size_t>(ret), true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocket::writeToStream(char const* buffer, std::size_t size)
{
    int ret = MOCK_FUNC(SSL_write)(ssl, buffer, size);
    if (ret <= 0)
    {
        int errorCode = MOCK_FUNC(SSL_get_error)(ssl, ret);
        switch (errorCode)
        {
            case SSL_ERROR_NONE:                return {0, true, false};
            case SSL_ERROR_ZERO_RETURN:         return {0, false, false};
            case SSL_ERROR_WANT_WRITE:          return {0, true, true};
            case SSL_ERROR_WANT_READ:           [[fallthrough]];
            case SSL_ERROR_WANT_CONNECT:        [[fallthrough]];
            case SSL_ERROR_WANT_ACCEPT:         [[fallthrough]];
            case SSL_ERROR_SYSCALL:             [[fallthrough]];
            case SSL_ERROR_SSL:
            {
                    ThorsLogAndThrowCritical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                        " writeToStream",
                        " :SocketCritical exception thrown.",
                        " errno = ", errorCode, " ", getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
                    );
            }
            case SSL_ERROR_WANT_X509_LOOKUP:    [[fallthrough]];
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:[[fallthrough]];
            case SSL_ERROR_WANT_ASYNC:          [[fallthrough]];
            case SSL_ERROR_WANT_ASYNC_JOB:      [[fallthrough]];
            default:
            {
                    ThorsLogAndThrowLogical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                        " writeToStream",
                        " :SocketUnknown exception thrown.",
                        " errno = ", errorCode, " ", getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
                    );
            }
        }
    }
    return {static_cast<std::size_t>(ret), true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocket::close()
{
    if (ssl)
    {
        // Close the file descriptor
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
    }
    Socket::close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SSocket::isConnected() const
{
    return ssl != nullptr;
}
