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

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(defaultMockedFunctions, MockConnectionSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(defaultMockedFunctions, MockConnectionSSocket::getActionSSocket());
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

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
    MOCK_SYS(SSL_connect,       connectLambda);
    MOCK_SYS(SSL_get_error,     getErrorLambda);

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(defaultMockedFunctions, MockConnectionSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(defaultMockedFunctions, MockConnectionSSocket::getActionSSocket(), {"SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get1_peer_certificate", "X509_free"});
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );


}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(TLS_client_method, [&]()    {defaultMockedFunctions.checkExpected("TLS_client_method");return nullptr;});

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
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

    // Override default behavior
    MOCK_SYS(SSL_CTX_new,       [&](SSL_METHOD const*)    {defaultMockedFunctions.checkExpected("SSL_CTX_new");return nullptr;});

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
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

    // Override default behavior
    MOCK_SYS(SSL_new,                   [&](SSL_CTX*)                   {defaultMockedFunctions.checkExpected("SSL_new");return nullptr;});

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(defaultMockedFunctions, MockConnectionSSocket::getActionSSocket());
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

    // Override default behavior
    MOCK_SYS(SSL_set_fd,                [&](SSL*,int)                   {defaultMockedFunctions.checkExpected("SSL_set_fd");return 0;});

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(defaultMockedFunctions, MockConnectionSSocket::getActionSSocket(), {"SSL_free"});
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

    MOCK_SYS(SSL_connect,               [&](SSL*)                       {defaultMockedFunctions.checkExpected("SSL_connect");return 0;});

    auto action = [&](){
        MockActionAddObject         checkSSLctx(defaultMockedFunctions, MockConnectionSSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(defaultMockedFunctions, MockConnectionSSocket::getActionSSocket(), {"SSL_get_error", "SSL_free"});
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

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action();
    );
}

TEST(ConnectionSSocketTest, Close)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

   SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
   SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddObject     checkClose(defaultMockedFunctions, MockAction{"Close", {"SSL_shutdown", "SSL_free", "close"}, {}, {}, {}});
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Read_OK)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Read", {"SSL_read"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SSL)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSSocketTest, Write_OK)
{
    MockConnectionSSocketUtil   defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(defaultMockedFunctions, MockAction{"Write", {"SSL_write"}, {}, {}});

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}



