#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "SimpleServer.h"


using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketClient;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketServer;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;

namespace ThorsAnvil::BuildTools::Mock
{
extern TA_Object Socket_BlockingGetAddrInfoOne;
extern TA_Object Socket_NonBlockingGetAddrInfoOne;
extern TA_Object Socket_NonBlockingGetAddrInfoTwoV1;
extern TA_Object Socket_NonBlockingGetAddrInfoTwoV2;
extern TA_Object Socket_NonBlockingGetAddrInfoTwoV3;
}

TEST(ConnectionSocketTest, Construct)
{
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV2)
    .run();
}

TEST(ConnectionSocketTest, ConstructGetAddrInfo)
{
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoOne)
    .run();
}

TEST(ConnectionSocketTest, ConstructGetAddrInfoTwoValueV1)
{
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
    .run();
}

TEST(ConnectionSocketTest, ConstructGetAddrInfoTwoValueV2)
{
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV2)
    .run();
}

TEST(ConnectionSocketTest, ConstructGetAddrInfoTwoValueV3)
{
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV3)
    .run();
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
        .expectCallTA(socket).inject().toReturn(-1)
        .expectCallTA(socket).inject().toReturn(-1)
        .expectCallTA(freeaddrinfo)
    .run();
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
#ifndef __WINNT__
    // Can't set h_errno (not a variable on windows)
    // So can't force a retry.
    h_errno = NO_DATA;
#endif
    TA_TestThrow([](){
#ifndef __WINNT__
        h_errno = HOST_NOT_FOUND; // TODO put inside function
#endif
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
        .expectCallTA(getAddressInfo).inject().toReturn(std::make_pair(-1, nullptr))
        .expectCallTA(thorCloseSocket)
    .run();
}

TEST(ConnectionSocketTest, GetHostCallFailsGetAddrInfo)
{
#ifndef __WINNT__
    // Can't set h_errno (not a variable on windows)
    // So can't force a retry.
    h_errno = NO_DATA;
#endif
    TA_TestThrow([](){
#ifndef __WINNT__
        h_errno = HOST_NOT_FOUND; // TODO put inside function
#endif
        SocketClient                socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoOne)
        .expectCallTA(getAddressInfo).inject().toReturn(std::make_pair(-1, nullptr))
        .expectCallTA(thorCloseSocket)
    .run();
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoOne)
        .expectCallTA(connect).inject().toReturn(-1)
        .expectCallTA(thorCloseSocket).toReturn(0)
        .expectCallTA(freeaddrinfo)
    .run();
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::Yes);
    })
    .expectObjectTA(Socket_BlockingGetAddrInfoOne)
    .run();
}

TEST(ConnectionSocketTest, CreateNonBlockingGetAddrInfo)
{
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com","80"}, Blocking::Yes);
    })
    .expectObjectTA(Socket_BlockingGetAddrInfoOne)
    .run();
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
    .run();
}

TEST(ConnectionSocketTest, CreateBlockingGetAddrInfo)
{
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com","80"}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoOne)
    .run();
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {THOR_SOCKET_ID(-1)}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_FALSE(socket.isConnected());
    })
    .run();
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {12}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    })
    .run();
}

TEST(ConnectionSocketTest, Close)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                socket({"github.com",80}, Blocking::No);

    TA_TestNoThrow([&](){
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    })
    .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
#ifdef __WINNT__
    // On Windows ConnectionSocket inherits from Connection (not ConnectionFileDescriptor)
    // So these tests have no meaning.
    GTEST_SKIP();
#else
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {33}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    })
    .run();
#endif
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
#ifdef __WINNT__
    // On Windows ConnectionSocket inherits from Connection (not ConnectionFileDescriptor)
    // So these tests have no meaning.
    GTEST_SKIP();
#else
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {34}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    })
    .run();
#endif
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
        .expectCallTA(thorSetSocketNonBlocking).inject().toReturn(-1)
    .run();
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
        socket.tryFlushBuffer();
    })
    .expectObjectTA(Socket_NonBlockingGetAddrInfoTwoV1)
        .expectCallTA(thorShutdownSocket).toReturn(0)
    .run();
}

TEST(ConnectionSocketTest, Protocol)
{
#ifdef THOR_DISABLE_TEST_WITH_PORT80
GTEST_SKIP();
#endif
    SocketSetUp         setup;

    SocketClient                socket({"github.com",80}, Blocking::No);
    EXPECT_EQ("http", socket.protocol());
}
    

