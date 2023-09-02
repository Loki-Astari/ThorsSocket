#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionSSocketUtilTest.h"
#include "test/ConnectionTest.h"

#include <vector>

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctxBuilder;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;

TEST(ConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    // Override default behavior
    auto connectLambda = [&](SSL*) {
        static int result[] ={-1, -1, -1, 1};
        static int r = 0;
        defaultMockedFunctions.checkExpected("SSL_connect");
        return result[r++];
    };
    auto getErrorLambda = [&](SSL const*, int) {
        static int result[] ={SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE};
        static int r = 0;
        defaultMockedFunctions.checkExpected("SSL_get_error");
        return result[r++];
    };
    defaultMockedFunctions.setAction("Slow Connect", {}, {"SSL_connect", "SSL_connect", "SSL_connect"}, {}, {"SSL_get_error", "SSL_get1_peer_certificate", "X509_free", "SSL_free"});
    MOCK_SYS(SSL_connect,       connectLambda);
    MOCK_SYS(SSL_get_error,     getErrorLambda);

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        action()
    );


}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    // Override default behavior
    MOCK_SYS(TLS_client_method, [&]()    {defaultMockedFunctions.checkExpected("TLS_client_method");return nullptr;});

    auto action = [&](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    // Override default behavior
    MOCK_SYS(SSL_CTX_new,       [&](SSL_METHOD const*)    {defaultMockedFunctions.checkExpected("SSL_CTX_new");return nullptr;});

    auto action = [&](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    // Override default behavior
    MOCK_SYS(SSL_new,                   [&](SSL_CTX*)                   {defaultMockedFunctions.checkExpected("SSL_new");return nullptr;});

    auto action = [&](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_free"});

    // Override default behavior
    MOCK_SYS(SSL_set_fd,                [&](SSL*,int)                   {defaultMockedFunctions.checkExpected("SSL_set_fd");return 0;});

    auto action = [&](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;
    defaultMockedFunctions.setAction("SSLctx", {"TLS_client_method", "SSL_CTX_new"}, {}, {"SSL_CTX_free"},
                                               {"SSL_CTX_ctrl", "SSL_CTX_set_cipher_list", "SSL_CTX_set_ciphersuites"});
    defaultMockedFunctions.setAction("Socket", {"socket", "gethostbyname", "connect"}, {}, {"close"}, {"fcntl"});
    defaultMockedFunctions.setAction("SSocket", {"SSL_new", "SSL_set_fd", "SSL_connect"}, {}, {"SSL_shutdown", "SSL_free"}, {"SSL_get1_peer_certificate", "X509_free", "SSL_get_error", "SSL_get_error", "SSL_free"});

    MOCK_SYS(SSL_connect,               [&](SSL*)                       {defaultMockedFunctions.checkExpected("SSL_connect");return 0;});

    auto action = [&](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, getSocketIdWorks)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Close)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
        socket.close();

        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Read_OK)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionSSocketTest, Write_OK)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    auto action = [](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        action()
    );
}



