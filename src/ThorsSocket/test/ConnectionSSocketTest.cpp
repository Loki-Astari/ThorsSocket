#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionTest.h"

#include <openssl/ssl.h>


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;


namespace ThorsAnvil::BuildTools::Mock
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
                .optionalTA(SSL_get_error).toReturn(SSL_ERROR_SYSCALL)
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
                .optionalTA(SSL_get_error).toReturn(SSL_ERROR_SYSCALL)
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
                .optionalTA(SSL_get_error).toReturn(SSL_ERROR_SYSCALL)
            );

static char const* addrList[] = {""};
static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=const_cast<char**>(addrList)};

TA_Object   Socket_Blocking(
                build()
                .expectInitTA(socket).toReturn(12)
                .expectInitTA(gethostbyname).toReturn(&result)
                .expectInitTA(connect)
                .expectDestTA(thorCloseSocket)
            );
TA_Object   Socket_NonBlocking(
                build()
                .expectInitTA(socket).toReturn(12)
                .expectInitTA(gethostbyname).toReturn(&result)
                .expectInitTA(connect)
                .expectInitTA(thorSetSocketNonBlocking).checkInput(12)
                .expectDestTA(thorCloseSocket)
            );
}

TEST(ConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    TA_TestNoThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocketClient       socket({"github.com",443 , ctx}, Blocking::Yes);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_Blocking)
    .expectObjectTA(SSocket)
    .run();
}

TEST(ConnectionSSocketTest, ValidateConnectIsReCalledOnNonBlockingSocket)
{
    TA_TestNoThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocketClient       socket({"github.com",443 , ctx}, Blocking::Yes);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_Blocking)
    .expectObjectTA(SSocket)
        .expectCallTA(SSL_connect).inject().anyOrder().toReturn(-1).toReturn(-1).toReturn(-1).toReturn(1)
        .expectCallTA(SSL_get_error).anyOrder().toReturn(SSL_ERROR_WANT_CONNECT).toReturn(SSL_ERROR_WANT_READ).toReturn(SSL_ERROR_WANT_WRITE)
        .expectCallTA(SSL_get1_peer_certificate).anyOrder().toReturn(reinterpret_cast<X509*>(0x08))
        .expectCallTA(X509_free).anyOrder().toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
    })
    .expectObjectTA(SSLctx_Client)
        .expectCallTA(TLS_client_method).inject().toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
    })
    .expectObjectTA(SSLctx_Client)
        .expectCallTA(SSL_CTX_new).inject().toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocketClient       socket({"github.com", 443, ctx}, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .expectCallTA(SSL_new).inject().toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocketClient       socket({"github.com", 443, ctx}, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .expectCallTA(SSL_set_fd).inject().toReturn(0)
        .expectCallTA(SSL_free).toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocketClient       socket({"github.com", 443, ctx}, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .expectCallTA(SSL_connect).inject().toReturn(0)
        .expectCallTA(SSL_free).toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, getSocketIdWorks)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocketClient           socket({"github.com", 443, ctx}, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    })
    .run();
}

TEST(ConnectionSSocketTest, Close)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocketClient           socket({"github.com", 443, ctx}, Blocking::No);

    TA_TestNoThrow([&](){
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    })
    .expectCallTA(SSL_shutdown).toReturn(1)
    .expectCallTA(SSL_free).toReturn(1)
    .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
#ifdef __WINNT__
    // On Windows ConnectionSocket inherits from Connection (not ConnectionFileDescriptor)
    // So these tests have no meaning.
    GTEST_SKIP();
#else
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocketClient           socket({"github.com", 443, ctx}, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    })
    .run();
#endif
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
#ifdef __WINNT__
    // On Windows ConnectionSocket inherits from Connection (not ConnectionFileDescriptor)
    // So these tests have no meaning.
    GTEST_SKIP();
#else
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocketClient           socket({"github.com", 443, ctx}, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    })
    .run();
#endif
}
