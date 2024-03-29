#include "ConnectionSSL.h"
#include "ThorsIOUtil/Utility.h"
#include "ThorsLogging/ThorsLogging.h"

#include <openssl/err.h>
// #include <sstream>

using namespace ThorsAnvil::ThorsSocket;

using ThorsAnvil::Utility::buildErrorMessage;
using ThorsAnvil::Utility::systemErrorMessage;

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
std::string SSLUtil::errorMessage()
{
    getInstance();
    std::stringstream message;
    for (long code = ERR_get_error(); code != 0; code = ERR_get_error())
    {
        message << "\t" << ERR_error_string(code, nullptr) << "\n";
    }
    return message.str();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::string SSLUtil::sslError(SSL* ssl, int ret)
{
    int error = SSL_get_error(ssl, ret);
    switch (error)
    {
        // The TLS/SSL I/O operation completed. This result code is returned if and only if ret > 0.
        case SSL_ERROR_NONE:            return "SSL_ERROR_NONE";

        // The TLS/SSL peer has closed the connection for writing by sending the "close notify" alert. No more data can be read. Note that SSL_ERROR_ZERO_RETURN does not necessarily indicate that the underlying transport has been closed.
        case SSL_ERROR_ZERO_RETURN:     return "SSL_ERROR_ZERO_RETURN";

        // The operation did not complete and can be retried later.
        // SSL_ERROR_WANT_READ is returned when the last operation was a read operation from a non-blocking BIO.
        // It means that not enough data was available at this time to complete the operation.
        // If at a later time the underlying BIO has data available for reading the same function can be called again.
        // SSL_read() and SSL_read_ex() can also set SSL_ERROR_WANT_READ when there is still unprocessed data available at either the SSL or the BIO layer, even for a blocking BIO.
        // See SSL_read(3) for more information.
        // SSL_ERROR_WANT_WRITE is returned when the last operation was a write to a non-blocking BIO and it was unable to sent all data to the BIO.
        // When the BIO is writeable again, the same function can be called again.
        // Note that the retry may again lead to an SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition.
        // There is no fixed upper limit for the number of iterations that may be necessary until progress becomes visible at application protocol level.
        // It is safe to call SSL_read() or SSL_read_ex() when more data is available even when the call that set this error was an SSL_write() or SSL_write_ex().
        // However if the call was an SSL_write() or SSL_write_ex(), it should be called again to continue sending the application data.
        // For socket BIOs (e.g. when SSL_set_fd() was used), select() or poll() on the underlying socket can be used to find out when the TLS/SSL I/O function should be retried.
        // Caveat: Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE.
        // In particular, SSL_read_ex(), SSL_read(), SSL_peek_ex(), or SSL_peek() may want to write data and SSL_write() or SSL_write_ex() may want to read data.
        // This is mainly because TLS/SSL handshakes may occur at any time during the protocol (initiated by either the client or the server); SSL_read_ex(), SSL_read(), SSL_peek_ex(), SSL_peek(), SSL_write_ex(), and SSL_write() will handle any pending handshakes.
        case SSL_ERROR_WANT_READ:       return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:      return "SSL_ERROR_WANT_WRITE";


        // The operation did not complete; the same TLS/SSL I/O function should be called again later.
        // The underlying BIO was not connected yet to the peer and the call would block in connect()/accept().
        // The SSL function should be called again when the connection is established.
        // These messages can only appear with a BIO_s_connect() or BIO_s_accept() BIO, respectively.
        // In order to find out, when the connection has been successfully established, on many platforms select() or poll() for writing on the socket file descriptor can be used.
        case SSL_ERROR_WANT_CONNECT:    return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:     return "SSL_ERROR_WANT_ACCEPT";

        // The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb() has asked to be called again.
        // The TLS/SSL I/O function should be called again later. Details depend on the application.
        case SSL_ERROR_WANT_X509_LOOKUP:return "SSL_ERROR_WANT_X509_LOOKUP";

#ifdef SSL_ERROR_WANT_ASYNC
        // The operation did not complete because an asynchronous engine is still processing data.
        // This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode(3) or SSL_set_mode(3) and an asynchronous capable engine is being used.
        // An application can determine whether the engine has completed its processing using select() or poll() on the asynchronous wait file descriptor.
        // This file descriptor is available by calling SSL_get_all_async_fds(3) or SSL_get_changed_async_fds(3).
        // The TLS/SSL I/O function should be called again later. The function must be called from the same thread that the original call was made from.
        case SSL_ERROR_WANT_ASYNC:      return "SSL_ERROR_WANT_ASYNC";
#endif

#ifdef SSL_ERROR_WANT_ASYNC_JOB
        // The asynchronous job could not be started because there were no async jobs available in the pool (see ASYNC_init_thread(3)).
        // This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode(3) or SSL_set_mode(3) and a maximum limit has been set on the async job pool through a call to ASYNC_init_thread(3).
        // The application should retry the operation after a currently executing asynchronous operation for the current thread has completed.
        case SSL_ERROR_WANT_ASYNC_JOB:  return "SSL_ERROR_WANT_ASYNC_JOB";
#endif

#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
        // The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb() has asked to be called again.
        // The TLS/SSL I/O function should be called again later. Details depend on the application.
        case SSL_ERROR_WANT_CLIENT_HELLO_CB: return "SSL_ERROR_WANT_CLIENT_HELLO_CB";
#endif

        // Some non-recoverable I/O error occurred.
        // The OpenSSL error queue may contain more information on the error.
        // For socket I/O on Unix systems, consult errno for details.
        case SSL_ERROR_SYSCALL:         return std::string("SSL_ERROR_SYSCALL: ") + systemErrorMessage();

        // This value can also be returned for other errors, check the error queue for details.
        case SSL_ERROR_SSL:             return "SSL_ERROR_SSL";
        default:
            break;
    }
    return "";
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLMethod::SSLMethod(SSLMethodType type)
    : method(nullptr)
{
    SSLUtil::getInstance();
    if (type == SSLMethodType::Client)
    {
        method = SSLv23_client_method();
    }
    else
    {
        method = SSLv23_server_method();
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLctx::SSLctx(SSLMethod& method)
    : ctx(SSL_CTX_new(method.method))
{
    if (!ctx)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_new() failed: ", SSLUtil::errorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLctx::SSLctx(SSLMethod& method, std::string const& certFile, std::string const& keyFile)
    : SSLctx(method)
{
#if (OPENSSL_VERSION_NUMBER >= 0x10002000)
    if (SSL_CTX_set_ecdh_auto(ctx, 1) != 1)
    {
        SSL_CTX_free(ctx);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_set_ecdh_auto() failed: ", SSLUtil::errorMessage());
    }
#endif
// SSL_CTX_set_cipher_list
    if (SSL_CTX_use_certificate_file(ctx, certFile.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        SSL_CTX_free(ctx);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_use_certificate_file() failed: ", SSLUtil::errorMessage());
    }
// SSL_CTX_set_default_passwd_cb_userdata
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile.c_str(), SSL_FILETYPE_PEM) != 1 )
    {
        SSL_CTX_free(ctx);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::SSLctx",
                         "SSLctx",
                         "SSL_CTX_use_PrivateKey_file() failed: ", SSLUtil::errorMessage());
    }
// SSL_CTX_check_private_key
// SSL_CTX_load_verify_locations
// SSL_CTX_set_verify

//Server Only
// SSL_CTX_load_and_set_client_CA_file
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSLctx::~SSLctx()
{
    SSL_CTX_free(ctx);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectionSSL::ConnectionSSL(SSLctx const& ctx, int fileDescriptor)
    : ConnectionNormal(fileDescriptor)
    , ssl(SSL_new(ctx.ctx))
{
    if (!ssl)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionSSL",
                         "ConnectionSSL",
                         "SSL_new() failed: ", SSLUtil::errorMessage());
    }
    if (SSL_set_fd(ssl, fileDescriptor) != 1)
    {
        SSL_free(ssl);
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionSSL",
                         "ConnectionSSL",
                         "SSL_set_fd() failed: ", SSLUtil::errorMessage());
    }

}

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectionSSL::~ConnectionSSL()
{
    // Close the file descriptor
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionSSL::acceptEstablishConnection()
{
    if (SSL_accept(ssl) != 1)
    {
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionSSL",
                         "accept",
                         "SSL_accept() failed: ", SSLUtil::errorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionSSL::connect(std::string const& host, int port)
{
    ConnectionNormal::connect(host, port);
    doConnect();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void ConnectionSSL::doConnect()
{
    int ret = SSL_connect(ssl);
    if (ret != 1)
    {
        // If this fails we should close the file descriptor.
        ThorsLogAndThrow("ThorsAnvil::ThorsSocket::ConnectionSSL",
                         "connect",
                         "SSL_connect() failed: ", SSLUtil::sslError(ssl, ret), " - ", SSLUtil::errorMessage());
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOResult ConnectionSSL::read(char* buffer, std::size_t len)
{
    ssize_t get = SSL_read(ssl, buffer, len);
    Result  r   = Result::OK;
    switch (SSL_get_error(ssl, get))
    {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        {
            r = Result::CriticalBug;
            break;
        }
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        {
            r = Result::Interupt;
            break;
        }
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        {
            r = Result::Timeout;
            break;
        }
        case SSL_ERROR_ZERO_RETURN:
        {
            r = Result::ConnectionClosed;
            break;
        }
        default:
        {
            r = Result::Unknown;
            break;
        }
    }
    return {get, r};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOResult ConnectionSSL::write(char const* buffer, std::size_t len)
{
    ssize_t put = SSL_write(ssl, buffer, len);
    Result  r   = Result::OK;
    switch (SSL_get_error(ssl, put))
    {
        case SSL_ERROR_NONE:
            break;
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
        {
            r = Result::CriticalBug;
            break;
        }
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        {
            r = Result::Interupt;
            break;
        }
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
        {
            r = Result::Timeout;
            break;
        }
        case SSL_ERROR_ZERO_RETURN:
        {
            r = Result::ConnectionClosed;
            break;
        }
        default:
        {
            r = Result::Unknown;
            break;
        }
    }
    return {put, r};
}

std::string ConnectionSSL::errorMessage(ssize_t result)
{
    return SSLUtil::sslError(ssl, result);
}
