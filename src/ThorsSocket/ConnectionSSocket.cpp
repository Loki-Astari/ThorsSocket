#include "ConnectionSSocket.h"
#include "ThorsLogging/ThorsLogging.h"
#include <iostream>

#include <openssl/err.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::SSocketStandard(SServerInfo const& ssocketInfo, int fd)
    : ssl(nullptr)
{
    initSSocket(ssocketInfo.ctx, std::move(ssocketInfo.certificate), fd);
    initSSocketServer();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::SSocketStandard(SSocketInfo const& ssocketInfo, int fd)
    : ssl(nullptr)
{
    initSSocket(ssocketInfo.ctx, std::move(ssocketInfo.certificate), fd);
    initSSocketClient();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::SSocketStandard(OpenSSocketInfo const& ssocketInfo, int fd)
    : ssl(nullptr)
{
    initSSocket(ssocketInfo.ctx, std::move(ssocketInfo.certificate), fd);
    initSSocketClient();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketStandard::~SSocketStandard()
{
    close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocket(SSLctx const& ctx, CertificateInfo&& certificate, int fd)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        int saveErrno = ERR_get_error();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocket",
            " :Failed on SSL_new.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    certificate.apply(ssl);

    int ret;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, fd)) != 1)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocket",
            " :Failed on SSL_set_fd.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocketServer()
{
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketStandard::initSSocketClient()
{
    int ret;
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
            int error = MOCK_FUNC(SSL_get_error)(ssl, ret);
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
        ssl = nullptr;
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClient",
            " :Failed on SSL_connect.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }


    X509* cert = MOCK_FUNC(SSL_get1_peer_certificate)(ssl);
    if (cert == nullptr)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketStandard",
            "initSSocketClient",
            " :Failed on SSL_get1_peer_certificate.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }
    MOCK_FUNC(X509_free)(cert);
}

void SSocketStandard::close()
{
    if (ssl)
    {
        // Close the file descriptor
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
char const* SSocketStandard::getSSErrNoStr(int)
{
    return "";
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
SSocketClient::SSocketClient(SSocketInfo const& ssocketInfo, Blocking blocking)
    : SocketClient(ssocketInfo, blocking)
    , secureSocketInfo(ssocketInfo, socketId(Mode::Read))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketClient::SSocketClient(OpenSSocketInfo const& ssocketInfo)
    : SocketClient(ssocketInfo)
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
void SSocketClient::tryFlushBuffer()
{
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocketClient::readFromStream(char* buffer, std::size_t size)
{
    SSL* ssl = secureSocketInfo.getSSL();

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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " readFromStream",
                        " :SocketCritical exception thrown.",
                        " errno = ", errorCode, " ", secureSocketInfo.getSSErrNoStr(errorCode),
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " readFromStream",
                        " :UnknownCritical exception thrown.",
                        " errno = ", errorCode, " ", secureSocketInfo.getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
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
                        " errno = ", errorCode, " ", secureSocketInfo.getSSErrNoStr(errorCode),
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient",
                        " writeToStream",
                        " :SocketUnknown exception thrown.",
                        " errno = ", errorCode, " ", secureSocketInfo.getSSErrNoStr(errorCode),
                        " msg >", ERR_error_string(errorCode, nullptr), "<"
                    );
            }
        }
    }
    return {static_cast<std::size_t>(ret), true, false};
}


THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketServer::SSocketServer(SServerInfo const& ssocketInfo, Blocking blocking)
    : SocketServer(ssocketInfo, blocking)
    , secureSocketInfo(ssocketInfo, socketId(Mode::Read))
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketServer::~SSocketServer()
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SSocketServer::isConnected() const
{
    return secureSocketInfo.isConnected();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketServer::close()
{
    secureSocketInfo.close();
    SocketServer::close();
}

std::unique_ptr<ThorsAnvil::ThorsSocket::ConnectionClient> SSocketServer::accept(Blocking /*blocking*/)
{
    return nullptr;
}
