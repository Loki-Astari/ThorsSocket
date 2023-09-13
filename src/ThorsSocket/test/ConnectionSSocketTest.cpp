#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"

#include <openssl/ssl.h>


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::BuildTools::Mock1::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock1::TA_TestNoThrow;


namespace ThorsAnvil::BuildTools::Mock1
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

TEST(ConnectionSSocketTest, ValidateAllFunctionsCalledCorrectOrder)
{
    TA_TestNoThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocket             socket(ctx, "github.com",443 , Blocking::Yes);
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
        SSocket             socket(ctx, "github.com",443 , Blocking::Yes);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_Blocking)
    .expectObjectTA(SSocket)
        .errorInitTA(SSL_connect).toReturn(-1).toReturn(-1).toReturn(-1).toReturn(1)
        .errorTA(SSL_get_error).toReturn(SSL_ERROR_WANT_CONNECT).toReturn(SSL_ERROR_WANT_READ).toReturn(SSL_ERROR_WANT_WRITE)
        .errorTA(SSL_get1_peer_certificate).toReturn(reinterpret_cast<X509*>(0x08))
        .errorTA(X509_free).toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_client_methodFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
    })
    .expectObjectTA(SSLctx_Client)
        .errorInitTA(TLS_client_method).toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSLCTX_SSL_TX_newFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
    })
    .expectObjectTA(SSLctx_Client)
        .errorInitTA(SSL_CTX_new).toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_newFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocket             socket(ctx, "github.com", 443, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .errorInitTA(SSL_new).toReturn(nullptr)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_set_fdFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocket             socket(ctx, "github.com", 443, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .errorInitTA(SSL_set_fd).toReturn(0)
        .errorTA(SSL_free).toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, CreateSSocket_SSL_connectFailed)
{
    TA_TestThrow([](){
        SSLctx              ctx{SSLMethodType::Client};
        SSocket             socket(ctx, "github.com", 443, Blocking::No);
    })
    .expectObjectTA(SSLctx_Client)
    .expectObjectTA(Socket_NonBlocking)
    .expectObjectTA(SSocket)
        .errorInitTA(SSL_connect).toReturn(0)
        .errorTA(SSL_free).toReturn(1)
    .run();
}

TEST(ConnectionSSocketTest, getSocketIdWorks)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.socketId(Mode::Write));
    })
    .run();
}

TEST(ConnectionSSocketTest, Close)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    })
    .expectCodeTA(SSL_shutdown).toReturn(1)
    .codeTA(SSL_free).toReturn(1)
    .codeTA(close).toReturn(0)
    .run();
}

TEST(ConnectionSSocketTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    })
    .run();
}

TEST(ConnectionSSocketTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    })
    .run();
}

void testReadFailure(Result expected, int errorCode)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    expected);
    })
    .expectCodeTA(SSL_read).toReturn(-1)
    .codeTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}

void testWriteFailure(Result expected, int errorCode)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     4);
        ASSERT_EQ(result.second,    expected);
    })
    .expectCodeTA(SSL_write).toReturn(-1)
    .codeTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}

TEST(ConnectionSSocketTest, Read_OK)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOResult result = socket.read(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    })
    .expectCodeTA(SSL_read).toReturn(8)
    .codeTA(SSL_get_error).toReturn(SSL_ERROR_NONE)
    .run();
}

TEST(ConnectionSSocketTest, Write_OK)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOResult result = socket.write(buffer, 12, 4);

        ASSERT_EQ(result.first,     12);
        ASSERT_EQ(result.second,    Result::OK);
    })
    .expectCodeTA(SSL_write).toReturn(8)
    .codeTA(SSL_get_error).toReturn(SSL_ERROR_NONE)
    .run();
}

TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_WRITE)                {testReadFailure(Result::CriticalBug, SSL_ERROR_WANT_WRITE);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CONNECT)              {testReadFailure(Result::CriticalBug, SSL_ERROR_WANT_CONNECT);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ACCEPT)               {testReadFailure(Result::CriticalBug, SSL_ERROR_WANT_ACCEPT);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_SYSCALL)                   {testReadFailure(Result::CriticalBug, SSL_ERROR_SYSCALL);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_SSL)                       {testReadFailure(Result::CriticalBug, SSL_ERROR_SSL);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_ZERO_RETURN)               {testReadFailure(Result::ConnectionClosed, SSL_ERROR_ZERO_RETURN);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_READ)                 {testReadFailure(Result::WouldBlock, SSL_ERROR_WANT_READ);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_X509_LOOKUP)          {testReadFailure(Result::Unknown, SSL_ERROR_WANT_X509_LOOKUP);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)      {testReadFailure(Result::Unknown, SSL_ERROR_WANT_CLIENT_HELLO_CB);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC)                {testReadFailure(Result::Unknown, SSL_ERROR_WANT_ASYNC);}
TEST(ConnectionSSocketTest, Read_SSL_ERROR_WANT_ASYNC_JOB)            {testReadFailure(Result::Unknown, SSL_ERROR_WANT_ASYNC_JOB);}


TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_READ)                {testWriteFailure(Result::CriticalBug, SSL_ERROR_WANT_READ);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CONNECT)             {testWriteFailure(Result::CriticalBug, SSL_ERROR_WANT_CONNECT);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ACCEPT)              {testWriteFailure(Result::CriticalBug, SSL_ERROR_WANT_ACCEPT);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_SYSCALL)                  {testWriteFailure(Result::CriticalBug, SSL_ERROR_SYSCALL);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_SSL)                      {testWriteFailure(Result::CriticalBug, SSL_ERROR_SSL);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_ZERO_RETURN)              {testWriteFailure(Result::ConnectionClosed, SSL_ERROR_ZERO_RETURN);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_WRITE)               {testWriteFailure(Result::WouldBlock, SSL_ERROR_WANT_WRITE);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_X509_LOOKUP)         {testWriteFailure(Result::Unknown, SSL_ERROR_WANT_X509_LOOKUP);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)     {testWriteFailure(Result::Unknown, SSL_ERROR_WANT_CLIENT_HELLO_CB);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC)               {testWriteFailure(Result::Unknown, SSL_ERROR_WANT_ASYNC);}
TEST(ConnectionSSocketTest, Write_SSL_ERROR_WANT_ASYNC_JOB)           {testWriteFailure(Result::Unknown, SSL_ERROR_WANT_ASYNC_JOB);}

