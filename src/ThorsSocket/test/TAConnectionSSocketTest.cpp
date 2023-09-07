#include <gtest/gtest.h>
#include "../ConnectionSSocket.h"
#include "test/ConnectionTest.h"
#include "test/MockHeaderInclude.h"
#include "coverage/MockHeaders2.h"
#include "test/Mock2DefaultThorsSocket.h"

#include <openssl/ssl.h>


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctxBuilder;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;
// using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
// using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
// using ThorsAnvil::BuildTools::Mock::MockActionAddCode;
// using ThorsAnvil::BuildTools::Mock::MockAction;


#define expectObjectTA(type, name)  expectObject<type>(ThorsAnvil::BuildTools::Mock2::Object_ ## type ## _ ## name)

#define expectInitTA(func)          expectInit(MOCK2_BUILD_MOCK_NAME(func))
#define expectDestTA(func)          expectDest(MOCK2_BUILD_MOCK_NAME(func))
#define optionalTA(func)            optional(MOCK2_BUILD_MOCK_NAME(func))


namespace ThorsAnvil::BuildTools::Mock2
{

TA_Object   Object_SSLctx_Client(
                build()
                .expectInitTA(TLS_client_method)
                .expectInitTA(SSL_CTX_new)
                .expectDestTA(SSL_CTX_free)
                .optionalTA(SSL_CTX_ctrl)
                .optionalTA(SSL_CTX_set_cipher_list)
                .optionalTA(SSL_CTX_set_ciphersuites)
                .optionalTA(SSL_CTX_set_default_passwd_cb)
                .optionalTA(SSL_CTX_set_default_passwd_cb_userdata)
                .optionalTA(SSL_CTX_use_certificate_file)
                .optionalTA(SSL_CTX_use_PrivateKey_file)
                .optionalTA(SSL_CTX_check_private_key)
                .optionalTA(SSL_CTX_set_default_verify_file)
                .optionalTA(SSL_CTX_set_default_verify_dir)
                .optionalTA(SSL_CTX_set_default_verify_store)
                .optionalTA(SSL_CTX_load_verify_file)
                .optionalTA(SSL_CTX_load_verify_dir)
                .optionalTA(SSL_CTX_load_verify_store)
                .optionalTA(sk_X509_NAME_new_null_wrapper)
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_CTX_set_verify)
                .optionalTA(SSL_CTX_set_client_CA_list)
                .optionalTA(ERR_get_error)
            );

TA_Object   Object_SSLctx_Server(
                build()
                .expectInitTA(TLS_server_method)
                .expectInitTA(SSL_CTX_new)
                .expectDestTA(SSL_CTX_free)
                .optionalTA(SSL_CTX_ctrl)
                .optionalTA(SSL_CTX_set_cipher_list)
                .optionalTA(SSL_CTX_set_ciphersuites)
                .optionalTA(SSL_CTX_set_default_passwd_cb)
                .optionalTA(SSL_CTX_set_default_passwd_cb_userdata)
                .optionalTA(SSL_CTX_use_certificate_file)
                .optionalTA(SSL_CTX_use_PrivateKey_file)
                .optionalTA(SSL_CTX_check_private_key)
                .optionalTA(SSL_CTX_set_default_verify_file)
                .optionalTA(SSL_CTX_set_default_verify_dir)
                .optionalTA(SSL_CTX_set_default_verify_store)
                .optionalTA(SSL_CTX_load_verify_file)
                .optionalTA(SSL_CTX_load_verify_dir)
                .optionalTA(SSL_CTX_load_verify_store)
                .optionalTA(sk_X509_NAME_new_null_wrapper)
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_CTX_set_verify)
                .optionalTA(SSL_CTX_set_client_CA_list)
                .optionalTA(ERR_get_error)
            );
TA_Object   Object_SSocket_(
                build()
                .expectInitTA(SSL_new)
                .expectInitTA(SSL_set_fd)
                .expectInitTA(SSL_connect)
                .expectInitTA(SSL_get1_peer_certificate)
                .expectInitTA(X509_free)
                .expectDestTA(SSL_shutdown)
                .expectDestTA(SSL_free)
                .optionalTA(SSL_ctrl)
                .optionalTA(SSL_set_cipher_list)
                .optionalTA(SSL_set_ciphersuites)
                .optionalTA(SSL_set_default_passwd_cb)
                .optionalTA(SSL_set_default_passwd_cb_userdata)
                .optionalTA(SSL_use_certificate_file)
                .optionalTA(SSL_use_PrivateKey_file)
                .optionalTA(SSL_check_private_key)
                .optionalTA(SSL_add_file_cert_subjects_to_stack)
                .optionalTA(SSL_add_dir_cert_subjects_to_stack)
                .optionalTA(SSL_add_store_cert_subjects_to_stack)
                .optionalTA(sk_X509_NAME_new_null_wrapper)
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_set_verify)
                .optionalTA(SSL_set_client_CA_list)
                .optionalTA(ERR_get_error)
            );
TA_Object   Object_Socket_Blocking(
                build()
                .expectInitTA(socket)
                .expectInitTA(gethostbyname)
                .expectInitTA(connect)
                .expectDestTA(close)
            );
TA_Object   Object_Socket_NonBlocking(
                build()
                .expectInitTA(socket)
                .expectInitTA(gethostbyname)
                .expectInitTA(connect)
                .expectInitTA(fcntl)
                .expectDestTA(close)
            );

}

TEST(TAConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    using ThorsAnvil::BuildTools::Mock2::TA_TestNoThrow;

    TA_TestNoThrow<Mock2DefaultThorsSocket>([](){
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    })
    .expectObjectTA(SSLctx, Client)
    //.expectObjectTA(Socket, NonBlocking)
    //.expectObjectTA(SSocket, )
    .run();
#if 0
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket());
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
#endif
}

#if 0
TEST(TAConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
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
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get_error", "SSL_connect", "SSL_get1_peer_certificate", "X509_free"});
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );


}

TEST(TAConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    MockDefaultThorsSocket         defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(TLS_client_method, []()    {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    MockDefaultThorsSocket         defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_CTX_new,       [](SSL_METHOD const*)    {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_new,                   [](SSL_CTX*)                   {return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket());
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_set_fd,                [](SSL*,int)                   {return 0;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_free"});
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    MOCK_SYS(SSL_connect,               [](SSL*)                       {return 0;});

    auto action = [](){
        MockActionAddObject         checkSSLctx(MockDefaultThorsSocket::getActionSSLctxClient());
        SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();

        MockActionAddObject         checkSocket(MockDefaultThorsSocket::getActionSocketNonBlocking());
        MockActionAddObject         checkSSocket(MockDefaultThorsSocket::getActionSSocket(), {"SSL_get_error", "SSL_free"});
        SSocket                     socket(ctx, "github.com", 443, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionSSocketTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action();
    );
}

TEST(TAConnectionSSocketTest, Close)
{
    MockDefaultThorsSocket     defaultMockedFunctions;

   SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
    SSocket                     socket(ctx, "github.com", 443, Blocking::No);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_SSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Read_OK)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_read,      [](SSL*, void*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_READ;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CONNECT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ACCEPT;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SYSCALL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_SSL)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_SSL;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_ZERO_RETURN;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_WRITE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_X509_LOOKUP;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_CLIENT_HELLO_CB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return -1;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_WANT_ASYNC_JOB;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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

TEST(TAConnectionSSocketTest, Write_OK)
{
    MockDefaultThorsSocket      defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(SSL_write,     [](SSL*, void const*, size_t) {return 8;});
    MOCK_SYS(SSL_get_error, [](SSL const*, int)     {return SSL_ERROR_NONE;});

    SSLctx                      ctx = SSLctxBuilder{SSLMethodType::Client}.build();
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
#endif



