#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"
#include <iostream>

#include <openssl/err.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::SSocketStandard(SSocketInfo const& ssocketInfo, int fd)
    : ssl{nullptr}
    , connectionFailed{false}
    , deferAction{DeferAction::None}
{
    initSSocket(ssocketInfo.ctx, fd);
    if (ssocketInfo.defer == DeferAccept::No)
    {
        YieldFunc nullYield = [](){return false;};
        initSSocketClientConnect(nullYield, nullYield);
    }
    else {
        deferAction = DeferAction::Connect;
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::SSocketStandard(OpenSSocketInfo const& ssocketInfo, int fd)
    : ssl{nullptr}
    , connectionFailed{false}
    , deferAction{DeferAction::None}
{
    initSSocket(ssocketInfo.ctx, fd);
    if (ssocketInfo.defer == DeferAccept::No)
    {
        YieldFunc nullYield = [](){return false;};
        initSSocketClientAccept(nullYield, nullYield);
    }
    else {
        deferAction = DeferAction::Accept;
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::~SSocketStandard()
{
    close();
}

extern "C"
THORS_SOCKET_HEADER_ONLY_INCLUDE
int printErrors(const char* s, std::size_t len, void* messageData)
{
    std::stringstream&  message = *reinterpret_cast<std::stringstream*>(messageData);
    message << "ERR: " << std::string_view(s, len) << "\n";
    return 0;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::string SSocketStandard::buildSSErrorMessage(int sslError)
{
    std::stringstream   message;
    switch (sslError)
    {
        case SSL_ERROR_NONE:
            message << "SSL: SSL_ERROR_NONE\n";
            break;
            //The TLS/SSL I/O operation completed. This result code is returned if and only if ret > 0.

        case SSL_ERROR_ZERO_RETURN:
            message << "SSL: SSL_ERROR_ZERO_RETURN\n";
            break;
            // The TLS/SSL peer has closed the connection for writing by sending the close_notify alert.
            // No more data can be read. Note that SSL_ERROR_ZERO_RETURN does not necessarily indicate
            // that the underlying transport has been closed.

        case SSL_ERROR_WANT_READ:
            message << "SSL: SSL_ERROR_WANT_READ\n";
            break;
        case SSL_ERROR_WANT_WRITE:
            message << "SSL: SSL_ERROR_WANT_WRITE\n";
            break;
            // The operation did not complete and can be retried later.
            //
            // SSL_ERROR_WANT_READ is returned when the last operation was a read operation from a nonblocking BIO.
            // It means that not enough data was available at this time to complete the operation. If at a later
            // time the underlying BIO has data available for reading the same function can be called again.
            //
            // SSL_read() and SSL_read_ex() can also set SSL_ERROR_WANT_READ when there is still unprocessed data
            // available at either the SSL or the BIO layer, even for a blocking BIO. See SSL_read(3) for more information.
            //
            // SSL_ERROR_WANT_WRITE is returned when the last operation was a write to a nonblocking BIO and it
            // was unable to sent all data to the BIO. When the BIO is writable again, the same function can be called again.
            //
            // Note that the retry may again lead to an SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE condition.
            // There is no fixed upper limit for the number of iterations that may be necessary until progress
            // becomes visible at application protocol level.
            //
            // It is safe to call SSL_read() or SSL_read_ex() when more data is available even when the call that
            // set this error was an SSL_write() or SSL_write_ex(). However, if the call was an SSL_write()
            // or SSL_write_ex(), it should be called again to continue sending the application data.
            //
            // For socket BIOs (e.g. when SSL_set_fd() was used), select() or poll() on the underlying socket
            // can be used to find out when the TLS/SSL I/O function should be retried.
            //
            // Caveat: Any TLS/SSL I/O function can lead to either of SSL_ERROR_WANT_READ and SSL_ERROR_WANT_WRITE.
            // In particular, SSL_read_ex(), SSL_read(), SSL_peek_ex(), or SSL_peek() may want to write data and SSL_write()
            // or SSL_write_ex() may want to read data. This is mainly because TLS/SSL handshakes may occur at any time
            // during the protocol (initiated by either the client or the server); SSL_read_ex(), SSL_read(),
            // SSL_peek_ex(), SSL_peek(), SSL_write_ex(), and SSL_write() will handle any pending handshakes.

        case SSL_ERROR_WANT_CONNECT:
            message << "SSL: SSL_ERROR_WANT_CONNECT\n";
            break;
        case SSL_ERROR_WANT_ACCEPT:
            message << "SSL: SSL_ERROR_WANT_ACCEPT\n";
            break;
            // The operation did not complete; the same TLS/SSL I/O function should be called again later.
            // The underlying BIO was not connected yet to the peer and the call would block in connect()/accept().
            // The SSL function should be called again when the connection is established.
            // These messages can only appear with a BIO_s_connect() or BIO_s_accept() BIO, respectively. In order
            // to find out, when the connection has been successfully established, on many platforms select()
            // or poll() for writing on the socket file descriptor can be used.

        case SSL_ERROR_WANT_X509_LOOKUP:
            message << "SSL: SSL_ERROR_WANT_X509_LOOKUP\n";
            break;
            // The operation did not complete because an application callback set by SSL_CTX_set_client_cert_cb()
            // has asked to be called again. The TLS/SSL I/O function should be called again later.
            // Details depend on the application.

        case SSL_ERROR_WANT_ASYNC:
            message << "SSL: SSL_ERROR_WANT_ASYNC\n";
            break;
            // The operation did not complete because an asynchronous engine is still processing data.
            // This will only occur if the mode has been set to SSL_MODE_ASYNC using SSL_CTX_set_mode(3)
            // or SSL_set_mode(3) and an asynchronous capable engine is being used. An application can determine
            // whether the engine has completed its processing using select() or poll() on the asynchronous wait
            // file descriptor. This file descriptor is available by calling SSL_get_all_async_fds(3) or
            // SSL_get_changed_async_fds(3). The TLS/SSL I/O function should be called again later. The function
            // must be called from the same thread that the original call was made from.

        case SSL_ERROR_WANT_ASYNC_JOB:
            message << "SSL: SSL_ERROR_WANT_ASYNC_JOB\n";
            break;
            // The asynchronous job could not be started because there were no async jobs available in the pool
            // (see ASYNC_init_thread(3)). This will only occur if the mode has been set to SSL_MODE_ASYNC
            // using SSL_CTX_set_mode(3) or SSL_set_mode(3) and a maximum limit has been set on the async job
            // pool through a call to ASYNC_init_thread(3). The application should retry the operation after
            // a currently executing asynchronous operation for the current thread has completed.

        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            message << "SSL: SSL_ERROR_WANT_CLIENT_HELLO_CB\n";
            break;
            // The operation did not complete because an application callback set by SSL_CTX_set_client_hello_cb()
            // has asked to be called again. The TLS/SSL I/O function should be called again later.
            // Details depend on the application.

        case SSL_ERROR_SYSCALL:
            message << "SSL: SSL_ERROR_SYSCALL\n";
            break;
            // Some non-recoverable, fatal I/O error occurred. The OpenSSL error queue may contain more
            // information on the error. For socket I/O on Unix systems, consult errno for details. If
            // this error occurs then no further I/O operations should be performed on the connection
            // and SSL_shutdown() must not be called.
            //
            // This value can also be returned for other errors, check the error queue for details.

        case SSL_ERROR_SSL:
            message << "SSL: SSL_ERROR_SSL\n";
            break;
        default:
            message << "No SSL Error\n";
    }
    ERR_print_errors_cb(printErrors, &message);
    return message.str();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocket(SSLctx const& ctx, int fd)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocket",
            " :Failed on SSL_new(): ",
            buildSSErrorMessage(0)
        );
    }

    int ret;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, fd)) != 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocket",
            " :Failed on SSL_set_fd(): ",
            buildSSErrorMessage(0)
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::deferInit(YieldFunc& rYield, YieldFunc& wYield)
{
    switch (deferAction)
    {
        case DeferAction::Connect:  initSSocketClientConnect(rYield, wYield);break;
        case DeferAction::Accept:   initSSocketClientAccept(rYield, wYield);break;
        case DeferAction::None:
            break;
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocketClientConnect(YieldFunc& rYield, YieldFunc& wYield)
{
    int ret;
    int error = 0;
    do
    {
        // TODO
        ret = MOCK_FUNC(SSL_connect)(ssl);
        if (ret != 1)
        {
            // If you open a non blocking connection.
            // It may take a while to get all the information you need
            // If you are simply waiting then you have to keep going.
            //
            // TODO: Opportunity for yield()?
            error = MOCK_FUNC(SSL_get_error)(ssl, ret);
            checkConnectionOK(error);
            switch (error)
            {
                case SSL_ERROR_WANT_READ:   rYield();continue;
                case SSL_ERROR_WANT_WRITE:  wYield();continue;
                case SSL_ERROR_WANT_CONNECT:wYield();continue;
                default:
                    break;
            }
        }
        break;
    }
    while (true);

    if (ret != 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClient",
            " :Failed on SSL_connect(): ",
            " errno = ", errno, " ", buildSSErrorMessage(error)
        );
    }


    X509* cert = MOCK_FUNC(SSL_get1_peer_certificate)(ssl);
    if (cert == nullptr)
    {
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClient",
            " :Failed on SSL_get1_peer_certificate(): ",
            buildSSErrorMessage(0)
        );
    }
    MOCK_FUNC(X509_free)(cert);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocketClientAccept(YieldFunc& rYield, YieldFunc& wYield)
{
    int status;
    int error = 0;
    do
    {
        // TODO
        status = SSL_accept(ssl);
        if (status != 1)
        {
            error = MOCK_FUNC(SSL_get_error)(ssl, status);
            checkConnectionOK(error);
            switch (error)
            {
                case SSL_ERROR_WANT_READ:   rYield();continue;
                case SSL_ERROR_WANT_WRITE:  wYield();continue;
                case SSL_ERROR_WANT_ACCEPT: wYield();continue;
                default:
                    break;
            }
        }
        break;
    }
    while (true);

    /* Check for error in handshake*/
    if (status < 1)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
        ThorsLog(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClientAccept",
            " :Failed on SSL_accept() ",
            " errno = ", error, " ", buildSSErrorMessage(error)
        );
    }

    /* Check for Client authentication error */
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
        ThorsLog(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClientAccept",
            " :Failed on SSL_get_verify_result(): ",
            buildSSErrorMessage(0)
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::close()
{
    if (ssl)
    {
        // Close the file descriptor
        if (!connectionFailed)
        {
            while (true)
            {
                int result = MOCK_FUNC(SSL_shutdown)(ssl);
                if (result == 1) {
                    break;
                }
                if (result == 0) {
                    continue;
                }
                int errorCode = SSL_get_error(ssl, result);
                if (errorCode == SSL_ERROR_WANT_READ)
                {
                    // If this is a non-blocking socket.
                    // Then this will busy loop waiting for a reply to confirm shutdown.
                    // TODO make this nicer.
                    continue;
                }

                ThorsLog(
                    "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
                    "close",
                    " :Failed on SSL_shutdown(): ",
                    buildSSErrorMessage(errorCode)
                );
                break;
            }
        }
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::externalyClosed()
{
    connectionFailed = true;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SSocketStandard::isConnected() const
{
    return ssl != nullptr;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSL* SSocketStandard::getSSL()   const
{
    return ssl;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::checkConnectionOK(int errorCode)
{
    connectionFailed = connectionFailed || errorCode == SSL_ERROR_SYSCALL || errorCode == SSL_ERROR_SSL;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketClient::SSocketClient(SSocketInfo const& ssocketInfo, Blocking blocking)
    : SocketClient(ssocketInfo, blocking)
    , secureSocketInfo(ssocketInfo, socketId(Mode::Read))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketClient::SSocketClient(SSocketServer& p, OpenSSocketInfo const& ssocketInfo, Blocking blocking)
    : SocketClient(p, ssocketInfo, blocking)
    , secureSocketInfo(ssocketInfo, socketId(Mode::Read))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketClient::~SSocketClient()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SSocketClient::isConnected() const
{
    return secureSocketInfo.isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketClient::close()
{
    secureSocketInfo.close();
    SocketClient::close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketClient::externalyClosed()
{
    secureSocketInfo.externalyClosed();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocketClient::readFromStream(char* buffer, std::size_t size)
{
    SSL* ssl = secureSocketInfo.getSSL();

    int ret = MOCK_FUNC(SSL_read)(ssl, buffer, size);
    if (ret <= 0)
    {
        int errorCode = MOCK_FUNC(SSL_get_error)(ssl, ret);
        secureSocketInfo.checkConnectionOK(errorCode);
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " readFromStream",
                        " :SocketCritical exception thrown.",
                        " :Failed on SSL_read(): ",
                        " errno = ", errorCode, " ", secureSocketInfo.buildSSErrorMessage(errorCode)
                    );
            }
            case SSL_ERROR_WANT_X509_LOOKUP:    [[fallthrough]];
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:[[fallthrough]];
            case SSL_ERROR_WANT_ASYNC:          [[fallthrough]];
            case SSL_ERROR_WANT_ASYNC_JOB:      [[fallthrough]];
            default:
            {
                    ThorsLogAndThrowLogical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " readFromStream",
                        " :UnknownCritical exception thrown.",
                        " :Failed on SSL_read(): ",
                        " errno = ", errorCode, " ", secureSocketInfo.buildSSErrorMessage(errorCode)
                    );
            }
        }
    }
    return {static_cast<std::size_t>(ret), true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocketClient::writeToStream(char const* buffer, std::size_t size)
{
    SSL* ssl = secureSocketInfo.getSSL();

    int ret = MOCK_FUNC(SSL_write)(ssl, buffer, size);
    if (ret <= 0)
    {
        int errorCode = MOCK_FUNC(SSL_get_error)(ssl, ret);
        secureSocketInfo.checkConnectionOK(errorCode);
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " writeToStream",
                        " :SocketCritical exception thrown.",
                        " :Failed on SSL_write(): ",
                        " errno = ", errorCode, " ", secureSocketInfo.buildSSErrorMessage(errorCode)
                    );
            }
            case SSL_ERROR_WANT_X509_LOOKUP:    [[fallthrough]];
            case SSL_ERROR_WANT_CLIENT_HELLO_CB:[[fallthrough]];
            case SSL_ERROR_WANT_ASYNC:          [[fallthrough]];
            case SSL_ERROR_WANT_ASYNC_JOB:      [[fallthrough]];
            default:
            {
                    ThorsLogAndThrowLogical(
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " writeToStream",
                        " :SocketUnknown exception thrown.",
                        " :Failed on SSL_write(): ",
                        " errno = ", errorCode, " ", secureSocketInfo.buildSSErrorMessage(errorCode)
                    );
            }
        }
    }
    return {static_cast<std::size_t>(ret), true, false};
}


THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketServer::SSocketServer(SServerInfo&& ssocketInfo, Blocking blocking)
    : SocketServer(std::move(ssocketInfo), blocking)
    , ctx(std::move(ssocketInfo.ctx))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
std::unique_ptr<ThorsAnvil::ThorsSocket::ConnectionClient> SSocketServer::accept(YieldFunc& yield, Blocking blocking, DeferAccept deferAccept)
{
    int     acceptedFd = SocketServer::acceptSocket(yield);

    return std::make_unique<SSocketClient>(*this, OpenSSocketInfo{static_cast<SOCKET_TYPE>(acceptedFd), ctx, deferAccept}, blocking);
}
