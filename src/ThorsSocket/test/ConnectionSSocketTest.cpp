#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionTest.h"

#include <vector>

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctxClient;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;

struct MockSocketSYSCalls
{
    std::function<HostEnt*(const char*)> getHostByNameMock =[&]  (char const*) {
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };

    MOCK_MEMBER(socket);
    MOCK_MEMBER(close);
    MOCK_MEMBER(gethostbyname);
    MOCK_MEMBER(connect);
    MOCK_TMEMBER(FctlType, fcntl);
    MOCK_MEMBER(TLS_client_method);
    MOCK_MEMBER(TLS_server_method);
    MOCK_MEMBER(SSL_CTX_new);
    MOCK_MEMBER(SSL_new);
    MOCK_MEMBER(SSL_set_fd);
    MOCK_MEMBER(SSL_connect);
    MOCK_MEMBER(SSL_shutdown);
    MOCK_MEMBER(SSL_free);
    MOCK_MEMBER(SSL_CTX_free);
    MOCK_MEMBER(SSL_CTX_use_certificate_file);
    MOCK_MEMBER(SSL_CTX_use_PrivateKey_file);
    MOCK_MEMBER(SSL_CTX_check_private_key);
    MOCK_MEMBER(SSL_get_peer_certificate);
    MOCK_MEMBER(SSL_set_default_passwd_cb);
    MOCK_MEMBER(SSL_set_default_passwd_cb_userdata);
    MOCK_MEMBER(SSL_use_certificate_file);
    MOCK_MEMBER(SSL_use_PrivateKey_file);
    MOCK_MEMBER(SSL_check_private_key);

    MockSocketSYSCalls()
        : MOCK_PARAM(socket,            [](int, int, int)       {return 12;})
        , MOCK_PARAM(close,             [](int)                 {return 0;})
        , MOCK_PARAM(gethostbyname, std::move(getHostByNameMock))
        , MOCK_PARAM(connect,           [](int, SocketAddr const*, unsigned int) {return 0;})
        , MOCK_PARAM(fcntl,             [](int, int, int)       {return 0;})
        , MOCK_PARAM(TLS_client_method, []()                    {return (SSL_METHOD*)1;})
        , MOCK_PARAM(TLS_server_method, []()                    {return (SSL_METHOD*)2;})
        , MOCK_PARAM(SSL_CTX_new,       [](SSL_METHOD const*)   {return (SSL_CTX*)2;})
        , MOCK_PARAM(SSL_new,           [](SSL_CTX*)            {return (SSL*)3;})
        , MOCK_PARAM(SSL_set_fd,        [](SSL*, int)           {return 1;})
        , MOCK_PARAM(SSL_connect,       [](SSL*)                {return 1;})
        , MOCK_PARAM(SSL_shutdown,      [](SSL*)                {return 1;})
        , MOCK_PARAM(SSL_free,          [](SSL*)                {return 1;})
        , MOCK_PARAM(SSL_CTX_free,      [](SSL_CTX*)            {return 1;})
        , MOCK_PARAM(SSL_CTX_use_certificate_file,      [](SSL_CTX*, char const*, int)  {return 1;})
        , MOCK_PARAM(SSL_CTX_use_PrivateKey_file,       [](SSL_CTX*, char const*, int)  {return 1;})
        , MOCK_PARAM(SSL_CTX_check_private_key,         [](SSL_CTX const*)              {return 1;})
        , MOCK_PARAM(SSL_get_peer_certificate,          [](SSL const*)                  {return (X509*)1;})
        , MOCK_PARAM(SSL_set_default_passwd_cb,         [](SSL*, int(*)(char*, int, int, void*)){})
        , MOCK_PARAM(SSL_set_default_passwd_cb_userdata,[](SSL*, void*)                 {})
        , MOCK_PARAM(SSL_use_certificate_file,          [](SSL*, char const*, int)      {return 1;})
        , MOCK_PARAM(SSL_use_PrivateKey_file,           [](SSL*, char const*, int)      {return 1;})
        , MOCK_PARAM(SSL_check_private_key,             [](SSL const*)                  {return 1;})
    {}
};

TEST(ConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    MockSocketSYSCalls  mockSysCalls;

    int callOrder = 1;
    int TLS_client_methodCalled = 0;
    int SSL_CTX_newCalled       = 0;
    int SSL_newCalled           = 0;
    int SSL_set_fdCalled        = 0;
    int SSL_connectCalled       = 0;
    int SSL_shutdownCalled      = 0;
    int SSL_freeCalled          = 0;
    int SSL_CTX_freeCalled      = 0;
    MOCK_SYS(TLS_client_method, [&]()                   {TLS_client_methodCalled = callOrder++;return (SSL_METHOD*)1;});
    MOCK_SYS(SSL_CTX_new,       [&](SSL_METHOD const*)  {SSL_CTX_newCalled = callOrder++;return (SSL_CTX*)2;});
    MOCK_SYS(SSL_new,           [&](SSL_CTX*)           {SSL_newCalled = callOrder++;return (SSL*)3;});
    MOCK_SYS(SSL_set_fd,        [&](SSL*, int)          {SSL_set_fdCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_connect,       [&](SSL*)               {SSL_connectCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_shutdown,      [&](SSL*)               {SSL_shutdownCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_free,          [&](SSL*)               {SSL_freeCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_CTX_free,      [&](SSL_CTX*)           {SSL_CTX_freeCalled = callOrder++;return 1;});

    {
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    }

    ASSERT_EQ(TLS_client_methodCalled, 1);
    ASSERT_EQ(SSL_CTX_newCalled,       2);
    ASSERT_EQ(SSL_newCalled,           3);
    ASSERT_EQ(SSL_set_fdCalled,        4);
    ASSERT_EQ(SSL_connectCalled,       5);
    ASSERT_EQ(SSL_shutdownCalled,      6);
    ASSERT_EQ(SSL_freeCalled,          7);
    ASSERT_EQ(SSL_CTX_freeCalled,      8);

}

TEST(ConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    MockSocketSYSCalls  mockSysCalls;

    int callOrder = 1;
    int TLS_client_methodCalled = 0;
    int SSL_CTX_newCalled       = 0;
    int SSL_newCalled           = 0;
    int SSL_set_fdCalled        = 0;
    std::vector<int> SSL_connectCalled;
    int SSL_shutdownCalled      = 0;
    int SSL_freeCalled          = 0;
    int SSL_CTX_freeCalled      = 0;
    MOCK_SYS(TLS_client_method, [&]()                   {TLS_client_methodCalled = callOrder++;return (SSL_METHOD*)1;});
    MOCK_SYS(SSL_CTX_new,       [&](SSL_METHOD const*)  {SSL_CTX_newCalled = callOrder++;return (SSL_CTX*)2;});
    MOCK_SYS(SSL_new,           [&](SSL_CTX*)           {SSL_newCalled = callOrder++;return (SSL*)3;});
    MOCK_SYS(SSL_set_fd,        [&](SSL*, int)          {SSL_set_fdCalled = callOrder++;return 1;});
    auto connectLambda        = [&](SSL*)               {static int result[] ={-1, -1, -1, 1};static int r = 0; SSL_connectCalled.push_back(callOrder++);return result[r++];};
    MOCK_SYS(SSL_connect,       connectLambda);
    auto getErrorLambda       = [&](SSL const*, int)    {static int result[] ={SSL_ERROR_WANT_CONNECT, SSL_ERROR_WANT_READ, SSL_ERROR_WANT_WRITE};static int r = 0;return result[r++];};
    MOCK_SYS(SSL_get_error,     getErrorLambda);
    MOCK_SYS(SSL_shutdown,      [&](SSL*)               {SSL_shutdownCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_free,          [&](SSL*)               {SSL_freeCalled = callOrder++;return 1;});
    MOCK_SYS(SSL_CTX_free,      [&](SSL_CTX*)           {SSL_CTX_freeCalled = callOrder++;return 1;});

    {
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    }


    ASSERT_EQ(TLS_client_methodCalled, 1);
    ASSERT_EQ(SSL_CTX_newCalled,       2);
    ASSERT_EQ(SSL_newCalled,           3);
    ASSERT_EQ(SSL_set_fdCalled,        4);
    ASSERT_EQ(SSL_connectCalled.size(),  4);
    ASSERT_EQ(SSL_connectCalled.back(), 8);
    SSL_connectCalled.pop_back();
    ASSERT_EQ(SSL_connectCalled.back(), 7);
    SSL_connectCalled.pop_back();
    ASSERT_EQ(SSL_connectCalled.back(), 6);
    SSL_connectCalled.pop_back();
    ASSERT_EQ(SSL_connectCalled.back(), 5);
    ASSERT_EQ(SSL_shutdownCalled,      9);
    ASSERT_EQ(SSL_freeCalled,          10);
    ASSERT_EQ(SSL_CTX_freeCalled,      11);
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(TLS_client_method, []()    {return nullptr;});

    auto action = [](){
        SSLctxClient                ctx;
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_CTX_new, [](SSL_METHOD const*)    {return nullptr;});

    auto action = [](){
        SSLctxClient                ctx;
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
TEST(ConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    MockSocketSYSCalls  mockSysCalls;

    int fdClosed = 0;
    MOCK_SYS(SSL_new, [](SSL_CTX*)  {return nullptr;});
    MOCK_SYS(close, [&fdClosed](int){++fdClosed;return 0;});

    auto action = [](){
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(1, fdClosed);
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    MockSocketSYSCalls  mockSysCalls;

    int fdClosed = 0;
    int sslFreeCount = 0;
    MOCK_SYS(SSL_set_fd, [](SSL*,int)           {return 0;});
    MOCK_SYS(SSL_free,   [&sslFreeCount](SSL*)  {++sslFreeCount;});
    MOCK_SYS(close,      [&fdClosed](int)       {++fdClosed;return 0;});

    auto action = [](){
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(sslFreeCount, 1);
    ASSERT_EQ(1, fdClosed);
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    MockSocketSYSCalls  mockSysCalls;

    int fdClosed = 0;
    int sslFreeCount = 0;
    MOCK_SYS(SSL_connect,   [](SSL*)               {return 0;});
    MOCK_SYS(SSL_free,      [&sslFreeCount](SSL*)  {++sslFreeCount;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)    {return SSL_ERROR_SSL;});
    MOCK_SYS(close,         [&fdClosed](int)       {++fdClosed;return 0;});

    auto action = [](){
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(sslFreeCount, 1);
    ASSERT_EQ(1, fdClosed);
}

TEST(ConnectionSSocketTest, DestructorCallsClose)
{
    MockSocketSYSCalls  mockSysCalls;

    int fdClosed = 0;
    int sslFreeCount = 0;
    MOCK_SYS(SSL_free,   [&sslFreeCount](SSL*)  {++sslFreeCount;});
    MOCK_SYS(close,      [&fdClosed](int)       {++fdClosed;return 0;});

    auto action = [](){
        SSLctxClient                ctx;
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_NO_THROW(
        action()
    );
    ASSERT_EQ(sslFreeCount, 1);
    ASSERT_EQ(1, fdClosed);
}

TEST(ConnectionSSocketTest, getSocketIdWorks)
{
    MockSocketSYSCalls  mockSysCalls;

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
}

TEST(ConnectionSSocketTest, Close)
{
    MockSocketSYSCalls  mockSysCalls;

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    socket.close();

    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockSocketSYSCalls  mockSysCalls;

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockSocketSYSCalls  mockSysCalls;

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_SSL)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::ConnectionClosed);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::WouldBlock);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Read_OK)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.read(buffer, 12, 4);

    ASSERT_EQ(result.first,     12);
    ASSERT_EQ(result.second,    Result::OK);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_SSL)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::CriticalBug);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::ConnectionClosed);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::WouldBlock);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     4);
    ASSERT_EQ(result.second,    Result::Unknown);
}

TEST(ConnectionSSocketTest, Write_OK)
{
    MockSocketSYSCalls  mockSysCalls;

    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctxClient                ctx;
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    char    buffer[12];
    IOResult result = socket.write(buffer, 12, 4);

    ASSERT_EQ(result.first,     12);
    ASSERT_EQ(result.second,    Result::OK);
}



