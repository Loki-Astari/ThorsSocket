#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"

#include <vector>

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;
using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock::MockActionAddCode;
using ThorsAnvil::BuildTools::Mock::MockAction;

TEST(ConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket());
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    auto connectLambda = [](SSL*) {
        static int result[] ={-1, -1, -1, 1};
        static int r = 0;
        return result[r++];
    };
    auto getErrorLambda = [](SSL const*, int) {
        static int result[] ={SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE};
        static int r = 0;
        return result[r++];
    };
    MOCK_SYS(SSL_connect,       connectLambda);
    MOCK_SYS(SSL_get_error,     getErrorLambda);

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get1_peer_certificate", "X509_free"});
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );


}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    MockDefaultThorsSocket         defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(TLS_client_method, []()    {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    MockDefaultThorsSocket         defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_CTX_new,       [](SSL_METHOD const*)    {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_new,                   [](SSL_CTX*)                   {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket());
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_set_fd,                [](SSL*,int)                   {return 0;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_free"});
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    MOCK_SYS(SSL_connect,               [](SSL*)                       {return 0;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx{SSLMethodType::Client};

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_get_error", "SSL_free"});
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action();
    );
}

TEST(ConnectionSSocketTest, Close)
{
    MockDefaultThorsSocket     defaultMockedFunctions;

   SSLctx                      ctx{SSLMethodType::Client};
   SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddObject     checkClose(MockAction{"Close", {"SSL_shutdown", "SSL_free", "close"}, {}, {}, {}});
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Read_OK)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Read", {"SSL_read"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    Result::Unknown);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSSocketTest, Write_OK)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx{SSLMethodType::Client};
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        MockActionAddCode   addCode(MockAction{"Write", {"SSL_write"}, {}, {}, {}}, {"SSL_get_error"} );

        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}



