#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSocket.h"

#include <iostream>
struct Mark
{
    Mark() {std::cerr << "Mark\n";}
    ~Mark(){std::cerr << "Mark Done\n";}
};

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketClient;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketServer;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;

namespace ThorsAnvil::BuildTools::Mock
{
extern TA_Object Socket_Blocking;
extern TA_Object Socket_NonBlocking;
}

TEST(ConnectionSocketTest, Construct)
{
    Mark  marker;
    TA_TestNoThrow([](){
        SocketClient                 socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    Mark  marker;
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(socket).inject().toReturn(-1)
    .run();
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
    Mark  marker;
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
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(gethostbyname).inject().toReturn(nullptr)
        .expectCallTA(thorCloseSocket)
    .run();
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
    Mark  marker;
#ifdef  __WINNT__
    // Can't set h_errno (not a variable on windows)
    // So can't force a retry.
    GTEST_SKIP();
#else
    h_errno = NO_DATA;
    TA_TestThrow([](){
        // TODO support setting h_errno depending on the call.
        MOCK_SYS(gethostbyname, [](char const*)
        {
            static int call =0;
            ++call;
            h_errno = (call == 1) ? TRY_AGAIN : HOST_NOT_FOUND;
            return nullptr;
        });
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        // This removes the gethostbyname from the init section.
        // We never enter the error section of the code.
        // The above MOCK_SYS catches the gethostbyname 
        .expectCallTA(gethostbyname).inject()
    .run();
#endif
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    Mark  marker;
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(connect).inject().toReturn(-1)
        .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    Mark  marker;
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::Yes);
    })
    .expectObjectTA(Socket_Blocking)
    .run();
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    Mark  marker;
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    Mark  marker;
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {THOR_SOCKET_ID(-1)}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_FALSE(socket.isConnected());
    })
    .run();
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    Mark  marker;
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
    Mark  marker;
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
    Mark  marker;
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
    Mark  marker;
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
    Mark  marker;
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorSetSocketNonBlocking).inject().toReturn(-1)
    .run();
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    Mark  marker;
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
        socket.tryFlushBuffer();
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorShutdownSocket).toReturn(0)
    .run();
}

TEST(ConnectionSocketTest, Protocol)
{
    SocketClient                socket({"github.com",80}, Blocking::No);
    EXPECT_EQ("http", socket.protocol());
}
    

