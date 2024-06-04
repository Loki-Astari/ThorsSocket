#include <gtest/gtest.h>
#include "ConnectionSSocket.h"
#include "test/ConnectionTest.h"

#include <openssl/ssl.h>


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctx;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;


TEST(ConnectionSSocketTestPart2, Read_OK)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOData  result = socket.readFromStream(buffer, 12);

        ASSERT_EQ(result.dataSize,     8);
        ASSERT_EQ(result.stillOpen,    true);
        ASSERT_EQ(result.blocked,      false);
    })
    .expectCallTA(SSL_read).toReturn(8)
    .expectCallTA(SSL_get_error).toReturn(SSL_ERROR_NONE)
    .run();
}

TEST(ConnectionSSocketTestPart2, Write_OK)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOData  result = socket.writeToStream(buffer, 12);

        ASSERT_EQ(result.dataSize,     8);
        ASSERT_EQ(result.stillOpen,    true);
        ASSERT_EQ(result.blocked,      false);
    })
    .expectCallTA(SSL_write).toReturn(8)
    .expectCallTA(SSL_get_error).toReturn(SSL_ERROR_NONE)
    .run();
}

void testReadFailure(IOData expected, int errorCode)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOData  result = socket.readFromStream(buffer, 12);

        ASSERT_EQ(result.dataSize,     expected.dataSize);
        ASSERT_EQ(result.stillOpen,    expected.stillOpen);
        ASSERT_EQ(result.blocked,      expected.blocked);
    })
    .expectCallTA(SSL_read).toReturn(-1)
    .expectCallTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}
template<typename Exception>
void testReadFailureException(int errorCode)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestThrow<Exception>([&](){
        char    buffer[12];
        socket.readFromStream(buffer, 12);
    })
    .expectCallTA(SSL_read).toReturn(-1)
    .expectCallTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}

void testWriteFailure(IOData expected, int errorCode)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestNoThrow([&](){
        char    buffer[12];
        IOData result = socket.writeToStream(buffer, 12);

        ASSERT_EQ(result.dataSize,     expected.dataSize);
        ASSERT_EQ(result.stillOpen,    expected.stillOpen);
        ASSERT_EQ(result.blocked,      expected.blocked);
    })
    .expectCallTA(SSL_write).toReturn(-1)
    .expectCallTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}
template<typename Exception>
void testWriteFailureException(int errorCode)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    SSLctx                  ctx{SSLMethodType::Client};
    SSocket                 socket(ctx, "github.com", 443, Blocking::No);

    TA_TestThrow<Exception>([&](){
        char    buffer[12];
        socket.writeToStream(buffer, 12);
    })
    .expectCallTA(SSL_write).toReturn(-1)
    .expectCallTA(SSL_get_error).toReturn(std::move(errorCode))
    .run();
}

TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_ZERO_RETURN)               {testReadFailure({0, false, false}, SSL_ERROR_ZERO_RETURN);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_READ)                 {testReadFailure({0, true, true}, SSL_ERROR_WANT_READ);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_WRITE)                {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_WRITE);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_CONNECT)              {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_CONNECT);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_ACCEPT)               {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_ACCEPT);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_SYSCALL)                   {testReadFailureException<std::runtime_error>(SSL_ERROR_SYSCALL);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_SSL)                       {testReadFailureException<std::runtime_error>(SSL_ERROR_SSL);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_X509_LOOKUP)          {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_X509_LOOKUP);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_CLIENT_HELLO_CB)      {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_CLIENT_HELLO_CB);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_ASYNC)                {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_ASYNC);}
TEST(ConnectionSSocketTestPart2, Read_SSL_ERROR_WANT_ASYNC_JOB)            {testReadFailureException<std::runtime_error>(SSL_ERROR_WANT_ASYNC_JOB);}


TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_ZERO_RETURN)              {testWriteFailure({0, false, false}, SSL_ERROR_ZERO_RETURN);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_WRITE)               {testWriteFailure({0, true, true}, SSL_ERROR_WANT_WRITE);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_READ)                {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_READ);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_CONNECT)             {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_CONNECT);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_ACCEPT)              {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_ACCEPT);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_SYSCALL)                  {testWriteFailureException<std::runtime_error>(SSL_ERROR_SYSCALL);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_SSL)                      {testWriteFailureException<std::runtime_error>(SSL_ERROR_SSL);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_X509_LOOKUP)         {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_X509_LOOKUP);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_CLIENT_HELLO_CB)     {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_CLIENT_HELLO_CB);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_ASYNC)               {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_ASYNC);}
TEST(ConnectionSSocketTestPart2, Write_SSL_ERROR_WANT_ASYNC_JOB)           {testWriteFailureException<std::runtime_error>(SSL_ERROR_WANT_ASYNC_JOB);}
