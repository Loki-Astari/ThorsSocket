#if 0
#include "ConnectionSSocket.h"

#include <map>
#include <openssl/err.h>
#include <iostream>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOResult;

SSLUtil::SSLUtil()
{
    SSL_load_error_strings();
    SSL_library_init();
    //OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, nullptr);
}

SSLUtil& SSLUtil::getInstance()
{
    static SSLUtil  instance;
    return instance;
}

SSLctx::~SSLctx()
{
    if (ctx) {
        MOCK_FUNC(SSL_CTX_free)(ctx);
    }
}

SSocket::SSocket(SSLctx const& ctx, std::string const& host, int port, Blocking blocking, CertificateInfo&& info)
    : Socket(host, port, blocking)
    , ssl(nullptr)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_new() failed: ", buildOpenSSLErrorMessage());
    }

    info.apply(ssl);

    int ret;
    int error;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, socketId(Mode::Read))) != 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_set_fd() failed: ", buildOpenSSLErrorMessage());
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
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSocket",
                         "SSocket",
                         "SSL_free() failed: ", buildErrorMessage(error));
    }


    X509* cert = MOCK_FUNC(SSL_get1_peer_certificate)(ssl);
    if (cert == nullptr)
    {
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSocket",
                         "SSocket",
                         "SSL_get1_peer_certificate() failed: ", buildOpenSSLErrorMessage());
    }
    MOCK_FUNC(X509_free)(cert);
}

SSocket::SSocket(int fd, SSLctx const& ctx, CertificateInfo&& info)
    : Socket(fd)
{
    /*Create new ssl object*/
    ssl = SSL_new(ctx.ctx);
    if (ssl == nullptr)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_new() failed: ", buildOpenSSLErrorMessage());
    }

    info.apply(ssl);

    /* Bind the ssl object with the socket*/
    SSL_set_fd(ssl, fd);

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
        int error = SSL_get_error(ssl, status);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_ccept() failed: ", buildErrorMessage(error));
    }

    /* Check for Client authentication error */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionType::SSocket",
                         "SSocket",
                         "SSL_get_verify_result() failed: ", buildOpenSSLErrorMessage());
    }
}

SSocket::~SSocket()
{
    close();
}

void SSocket::tryFlushBuffer()
{
}

IOResult SSocket::read(char* buffer, std::size_t size, std::size_t read)
{
    int ret = MOCK_FUNC(SSL_read)(ssl, buffer + read, size - read);
    Result  result   = Result::OK;
    switch (MOCK_FUNC(SSL_get_error)(ssl, ret))
    {
        case SSL_ERROR_NONE:
        {
            read += ret;
            // Note result is Already OK.
            break;
        }
        case SSL_ERROR_WANT_WRITE:          // should not happen on a read.
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            result = Result::CriticalBug;
            break;
        case SSL_ERROR_ZERO_RETURN:
            result = Result::ConnectionClosed;
            break;
        case SSL_ERROR_WANT_READ:
            result = Result::WouldBlock;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:    // Not sure what to do here.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        default:
        {
            result = Result::Unknown;
            break;
        }
    }
    return {read, result};
}

IOResult SSocket::write(char const* buffer, std::size_t size, std::size_t written)
{
    int ret = MOCK_FUNC(SSL_write)(ssl, buffer + written, size - written);
    Result  result   = Result::OK;
    switch (MOCK_FUNC(SSL_get_error)(ssl, ret))
    {
        case SSL_ERROR_NONE:
        {
            written += ret;
            // Note result is Already OK.
            break;
        }
        case SSL_ERROR_WANT_READ:           // should not happen on a read.
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            result = Result::CriticalBug;
            break;
        case SSL_ERROR_ZERO_RETURN:
            result = Result::ConnectionClosed;
            break;
        case SSL_ERROR_WANT_WRITE:
            result = Result::WouldBlock;
            break;
        case SSL_ERROR_WANT_X509_LOOKUP:    // Not sure what to do here.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        default:
        {
            result = Result::Unknown;
            break;
        }
    }
    return {written, result};
}

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

bool SSocket::isConnected() const
{
    return ssl != nullptr;
}

std::string SSocket::errorMessage(ssize_t ret)
{
    int error = MOCK_FUNC(SSL_get_error)(ssl, ret);
    return buildErrorMessage(error);
}

std::string SSocket::buildErrorMessage(int error)
{
    static const std::map<int, char const*> errorString =
    {
        {SSL_ERROR_NONE, "SSL_ERROR_NONE"},                         {SSL_ERROR_NONE, "SSL_ERROR_NONE"},
        {SSL_ERROR_WANT_READ, "SSL_ERROR_WANT_READ"},               {SSL_ERROR_WANT_WRITE, "SSL_ERROR_WANT_WRITE"},
        {SSL_ERROR_WANT_CONNECT, "SSL_ERROR_WANT_CONNECT"},         {SSL_ERROR_WANT_ACCEPT, "SSL_ERROR_WANT_ACCEPT"},
        {SSL_ERROR_WANT_X509_LOOKUP, "SSL_ERROR_WANT_X509_LOOKUP"}, {SSL_ERROR_WANT_ASYNC, "SSL_ERROR_WANT_ASYNC"},
        {SSL_ERROR_WANT_ASYNC_JOB, "SSL_ERROR_WANT_ASYNC_JOB"},     {SSL_ERROR_WANT_CLIENT_HELLO_CB, "SSL_ERROR_WANT_CLIENT_HELLO_CB"},
        {SSL_ERROR_SYSCALL, "SSL_ERROR_SYSCALL"},                   {SSL_ERROR_SSL, "SSL_ERROR_SSL"}
    };
    auto find = errorString.find(error);
    char const* errorName = find == errorString.end() ? "Unknown" : find->second;

    std::stringstream result;
    result << "ConnectionType::SSocket: SSLErrorCode =" << error << "(" << errorName << "): msg: " << buildOpenSSLErrorMessage(false);
    return result.str();
}
#endif
