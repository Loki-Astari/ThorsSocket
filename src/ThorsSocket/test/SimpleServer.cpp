#include "test/SimpleServer.h"

#include <iostream>
struct Mark
{
    Mark() {std::cerr << "Mark\n";}
    ~Mark(){std::cerr << "Mark Done\n";}
};

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketBase::SSocketBase(SSocketInfo const& ssocketInfo, Blocking blocking)
    : SocketClient(ssocketInfo, blocking)
    , ssl(nullptr)
{
    initSSocket(ssocketInfo.ctx);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketBase::SSocketBase(OpenSSocketInfo const& ssocketInfo)
    : SocketClient(*reinterpret_cast<SocketServer*>(32), ssocketInfo, Blocking::Yes)
{
    initSSocket(ssocketInfo.ctx);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SSocketBase::~SSocketBase()
{
    close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketBase::initSSocket(SSLctx const& ctx)
{
    ssl = MOCK_FUNC(SSL_new)(ctx.ctx);
    if (!ssl)
    {
        int saveErrno = ERR_get_error();
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
            "SSocketBase",
            " :Failed on SSL_new.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }

    int ret;
    if ((ret = MOCK_FUNC(SSL_set_fd)(ssl, socketId(Mode::Read))) != 1)
    {
        int saveErrno = MOCK_FUNC(SSL_get_error)(ssl, ret);
        MOCK_FUNC(SSL_free)(ssl);
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
            "SSocketBase",
            " :Failed on SSL_set_fd.",
            " errno = ", errno, " ", getSSErrNoStr(saveErrno),
            " msg >", ERR_error_string(saveErrno, nullptr), "<"
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketBase::tryFlushBuffer()
{
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SSocketBase::close()
{
    if (ssl)
    {
        // Close the file descriptor
        MOCK_FUNC(SSL_shutdown)(ssl);
        MOCK_FUNC(SSL_free)(ssl);
        ssl = nullptr;
    }
    SocketClient::close();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SSocketBase::isConnected() const
{
    return ssl != nullptr;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
IOData SSocketBase::readFromStream(char* buffer, std::size_t size)
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
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
IOData SSocketBase::writeToStream(char const* buffer, std::size_t size)
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
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
                        "ThorsAnvil::ThorsSocket::ConnectionType::SSocketBase",
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


