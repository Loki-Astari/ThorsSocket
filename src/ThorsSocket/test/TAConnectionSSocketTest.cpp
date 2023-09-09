#include <gtest/gtest.h>
#include "../ConnectionSSocket.h"
#include "test/ConnectionTest.h"
#include "test/MockHeaderInclude.h"
#include "coverage/MockHeaders2.h"
#include "test/Mock2DefaultThorsSocket.h"

#include <openssl/ssl.h>


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;
// using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
// using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
// using ThorsAnvil::BuildTools::Mock::MockActionAddCode;
// using ThorsAnvil::BuildTools::Mock::MockAction;


#define expectObjectTA(name)        expectObject(ThorsAnvil::BuildTools::Mock2:: name)
#define errorTA(func)               error(MOCK2_BUILD_MOCK_NAME(func))

#define expectInitTA(func)          expectInit(MOCK2_BUILD_MOCK_NAME(func))
#define expectDestTA(func)          expectDest(MOCK2_BUILD_MOCK_NAME(func))
#define optionalTA(func)            optional(MOCK2_BUILD_MOCK_NAME(func))


namespace ThorsAnvil::BuildTools::Mock2
{

TA_Object   SSLctx_Client(
                build()
                .expectInitTA(TLS_client_method).toReturn(reinterpret_cast<SSL_METHOD*>(0x08))
                .expectInitTA(SSL_CTX_new).toReturn(reinterpret_cast<SSL_CTX*>(0x18))
                .expectDestTA(SSL_CTX_free).toReturn(1)
                .optionalTA(SSL_CTX_ctrl).toReturn(1)
                .optionalTA(SSL_CTX_set_cipher_list).toReturn(1)
                .optionalTA(SSL_CTX_set_ciphersuites).toReturn(1)
                .optionalTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
                .optionalTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
                .optionalTA(SSL_CTX_use_certificate_file).toReturn(1)
                .optionalTA(SSL_CTX_use_PrivateKey_file).toReturn(1)
                .optionalTA(SSL_CTX_check_private_key).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_file).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_dir).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_store).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_file).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_dir).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_store).toReturn(1)
                .optionalTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_CTX_set_verify).toReturn(1)
                .optionalTA(SSL_CTX_set_client_CA_list).toReturn(1)
                .optionalTA(ERR_get_error).toReturn(0)
            );

TA_Object   SSLctx_Server(
                build()
                .expectInitTA(TLS_server_method).toReturn(reinterpret_cast<SSL_METHOD*>(0x10))
                .expectInitTA(SSL_CTX_new).toReturn(reinterpret_cast<SSL_CTX*>(0x18))
                .expectDestTA(SSL_CTX_free).toReturn(1)
                .optionalTA(SSL_CTX_ctrl).toReturn(1)
                .optionalTA(SSL_CTX_set_cipher_list).toReturn(1)
                .optionalTA(SSL_CTX_set_ciphersuites).toReturn(1)
                .optionalTA(SSL_CTX_set_default_passwd_cb).toReturn(1)
                .optionalTA(SSL_CTX_set_default_passwd_cb_userdata).toReturn(1)
                .optionalTA(SSL_CTX_use_certificate_file).toReturn(1)
                .optionalTA(SSL_CTX_use_PrivateKey_file).toReturn(1)
                .optionalTA(SSL_CTX_check_private_key).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_file).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_dir).toReturn(1)
                .optionalTA(SSL_CTX_set_default_verify_store).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_file).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_dir).toReturn(1)
                .optionalTA(SSL_CTX_load_verify_store).toReturn(1)
                .optionalTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_CTX_set_verify).toReturn(1)
                .optionalTA(SSL_CTX_set_client_CA_list).toReturn(1)
                .optionalTA(ERR_get_error).toReturn(0)
            );
TA_Object   SSocket(
                build()
                .expectInitTA(SSL_new).toReturn(reinterpret_cast<SSL*>(0x20))
                .expectInitTA(SSL_set_fd).toReturn(1)
                .expectInitTA(SSL_connect).toReturn(1)
                .expectInitTA(SSL_get1_peer_certificate).toReturn(reinterpret_cast<X509*>(0x08))
                .expectInitTA(X509_free).toReturn(1)
                .expectDestTA(SSL_shutdown).toReturn(1)
                .expectDestTA(SSL_free).toReturn(1)
                .optionalTA(SSL_ctrl).toReturn(1)
                .optionalTA(SSL_set_cipher_list).toReturn(1)
                .optionalTA(SSL_set_ciphersuites).toReturn(1)
                .optionalTA(SSL_set_default_passwd_cb).toReturn(1)
                .optionalTA(SSL_set_default_passwd_cb_userdata).toReturn(1)
                .optionalTA(SSL_use_certificate_file).toReturn(1)
                .optionalTA(SSL_use_PrivateKey_file).toReturn(1)
                .optionalTA(SSL_check_private_key).toReturn(1)
                .optionalTA(SSL_add_file_cert_subjects_to_stack).toReturn(1)
                .optionalTA(SSL_add_dir_cert_subjects_to_stack).toReturn(1)
                .optionalTA(SSL_add_store_cert_subjects_to_stack).toReturn(1)
                .optionalTA(sk_X509_NAME_new_null_wrapper).toReturn(reinterpret_cast<STACK_OF(X509_NAME)*>(0x08))
                .optionalTA(sk_X509_NAME_free_wrapper)
                .optionalTA(sk_X509_NAME_pop_free_wrapper)
                .optionalTA(SSL_set_verify).toReturn(1)
                .optionalTA(SSL_set_client_CA_list).toReturn(1)
                .optionalTA(ERR_get_error).toReturn(0)
            );

static char* addrList[] = {""};
static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=addrList};

TA_Object   Socket_Blocking(
                build()
                .expectInitTA(socket).toReturn(12)
                .expectInitTA(gethostbyname).toReturn(&result)
                .expectInitTA(connect)
                .expectDestTA(close)
            );
TA_Object   Socket_NonBlocking(
                build()
                .expectInitTA(socket).toReturn(12)
                .expectInitTA(gethostbyname).toReturn(&result)
                .expectInitTA(connect)
                .expectInitTA(fcntl)
                .expectDestTA(close)
            );
}

TEST(TAConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    using ThorsAnvil::BuildTools::Mock2::TA_TestNoThrow;

    TA_TestNoThrow<Mock2DefaultThorsSocket>([](){
        SSLctx                      ctx{SSLMethodType::Client};
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_Blocking)
    .expectObjectTA(SSocket)
    .run();
}

TEST(TAConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    using ThorsAnvil::BuildTools::Mock2::TA_TestNoThrow;

    TA_TestNoThrow<Mock2DefaultThorsSocket>([](){
        SSLctx                      ctx{SSLMethodType::Client};
        SSocket                     socket(ctx, "github.com",443 , Blocking::Yes);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_Blocking)
    .expectObjectTA(SSocket)
        .errorTA(SSL_connect).toReturn(-1).toReturn(-1).toReturn(-1).toReturn(1)
        .errorTA(SSL_get_error).toReturn(SSL_ERROR_WANT_CONNECT).toReturn(SSL_ERROR_WANT_READ).toReturn(SSL_ERROR_WANT_WRITE)
        .errorTA(SSL_get1_peer_certificate).toReturn(reinterpret_cast<X509*>(0x08))
        .errorTA(X509_free).toReturn(1)
    .run();
}

TEST(TAConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    using ThorsAnvil::BuildTools::Mock2::TA_TestThrow;

    TA_TestThrow<Mock2DefaultThorsSocket, std::runtime_error>([](){
        SSLctx                      ctx{SSLMethodType::Client};
    })
    .expectObjectTA(SSLctx_Client)
        .errorTA(TLS_client_method).toReturn(nullptr)
    .run();
}

#if 0
TEST(TAConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
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

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_newFailed)
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

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
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

TEST(TAConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
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

TEST(TAConnectionSSocketTest, getSocketIdWorks)
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

TEST(TAConnectionSSocketTest, Close)
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

TEST(TAConnectionSSocketTest, ReadFDSameAsSocketId)
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

TEST(TAConnectionSSocketTest, WriteFDSameAsSocketId)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_SSL)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)
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

TEST(TAConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)
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

TEST(TAConnectionSSocketTest, Read_OK)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_SSL)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)
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

TEST(TAConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)
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

TEST(TAConnectionSSocketTest, Write_OK)
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
#endif



