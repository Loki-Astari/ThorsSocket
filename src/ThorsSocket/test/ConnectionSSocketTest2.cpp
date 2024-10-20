#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSSocket.h"

#include <iostream>

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;

namespace ThorsAnvil::BuildTools::Mock
{

extern TA_Object   SSLctx_Client;
extern TA_Object   SSocket;
extern TA_Object   Socket_NonBlocking;

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
