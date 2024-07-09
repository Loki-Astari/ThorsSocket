#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSocket.h"

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
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
    TA_TestNoThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    TA_TestThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(socket).inject().toReturn(-1)
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
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(gethostbyname).inject().toReturn(nullptr)
        .expectCallTA(thorCloseSocket)
    .run();
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
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
        Socket                      socket({"github.com",80}, Blocking::No);
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
    TA_TestThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(connect).inject().toReturn(-1)
        .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    TA_TestNoThrow([](){
        Socket                      socket({"github.com",80}, Blocking::Yes);
    })
    .expectObjectTA(Socket_Blocking)
    .run();
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    TA_TestNoThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    Socket                        socket({THOR_SOCKET_ID(-1)});

    TA_TestNoThrow([&](){
        ASSERT_FALSE(socket.isConnected());
    })
    .run();
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    Socket                        socket({12});

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    })
    .run();
}

TEST(ConnectionSocketTest, Close)
{
    MockAllDefaultFunctions       defaultMockedFunctions;
    Socket                      socket({"github.com",80}, Blocking::No);

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
    Socket                        socket({33});

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
    Socket                        socket({34});

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    })
    .run();
#endif
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
    TA_TestThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorSetSocketNonBlocking).inject().toReturn(-1)
    .run();
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    TA_TestNoThrow([](){
        Socket                      socket({"github.com",80}, Blocking::No);
        socket.tryFlushBuffer();
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorShutdownSocket).toReturn(0)
    .run();
}
