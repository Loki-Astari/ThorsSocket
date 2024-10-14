#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSocket.h"

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

class X2
{
	public:
		X2() 	{std::cerr << "Construct X2\n";}
		~X2()	{std::cerr << "Destroy   X2\n";}
};
TEST(ConnectionSocketTest, Construct)
{
    X2  mark;
    std::cerr << "Construct\n";
    TA_TestNoThrow([](){
        std::cerr << "Construct 1\n";
        SocketClient                 socket({"github.com",80}, Blocking::No);
        std::cerr << "Construct 2\n";
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
    std::cerr << "Construct DON\n";
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    X2  mark;
    std::cerr << "SocketCallFails\n";
    TA_TestThrow([](){
        std::cerr << "SocketCallFails 1\n";
        SocketClient                socket({"github.com",80}, Blocking::No);
        std::cerr << "SocketCallFails 2\n";
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(socket).inject().toReturn(-1)
    .run();
    std::cerr << "SocketCallFails DONE\n";
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
	X2	mark;
	std::cerr << "GetHostCallFails\n";

#ifndef __WINNT__
    // Can't set h_errno (not a variable on windows)
    // So can't force a retry.
    h_errno = NO_DATA;
#endif
	std::cerr << "GetHostCallFails 1\n";
    TA_TestThrow([](){
#ifndef __WINNT__
        h_errno = HOST_NOT_FOUND; // TODO put inside function
#endif
		std::cerr << "GetHostCallFails 2\n";
        SocketClient                socket({"github.com",80}, Blocking::No);
		std::cerr << "GetHostCallFails 3\n";
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(gethostbyname).inject().toReturn(nullptr)
        .expectCallTA(thorCloseSocket)
    .run();
	std::cerr << "GetHostCallFails DONE\n";
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
	X2	mark;
	std::cerr << "GetHostCallFailsTryAgain\n";
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
	std::cerr << "GetHostCallFailsTryAgain DONE\n";
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
	X2	mark;
	std::cerr << "ConnectCallFailes\n";
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(connect).inject().toReturn(-1)
        .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
	std::cerr << "ConnectCallFailes DONE\n";
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
	X2	mark;
	std::cerr << "CreateNonBlocking\n";
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::Yes);
    })
    .expectObjectTA(Socket_Blocking)
    .run();
	std::cerr << "CreateNonBlocking DONE\n";
}

TEST(ConnectionSocketTest, CreateBlocking)
{
	X2	mark;
	std::cerr << "CreateBlocking\n";
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
    .run();
	std::cerr << "CreateBlocking DONE\n";
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
	X2	mark;
	std::cerr << "notValidOnMinusOne\n";
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {THOR_SOCKET_ID(-1)}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_FALSE(socket.isConnected());
    })
    .run();
	std::cerr << "notValidOnMinusOne DONE\n";
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
	X2	mark;
	std::cerr << "getSocketIdWorks\n";
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                  socket(*reinterpret_cast<SocketServer*>(32), {12}, Blocking::Yes);

    TA_TestNoThrow([&](){
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    })
    .run();
	std::cerr << "getSocketIdWorks DONE\n";
}

TEST(ConnectionSocketTest, Close)
{
	X2	mark;
	std::cerr << "Close\n";
    MockAllDefaultFunctions       defaultMockedFunctions;
    SocketClient                socket({"github.com",80}, Blocking::No);

    TA_TestNoThrow([&](){
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    })
    .expectCallTA(thorCloseSocket).toReturn(0)
    .run();
	std::cerr << "Close DONE\n";
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
	X2	mark;
	std::cerr << "ReadFDSameAsSocketId\n";
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
	std::cerr << "ReadFDSameAsSocketId DONE\n";
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
	X2	mark;
	std::cerr << "WriteFDSameAsSocketId\n";
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
	std::cerr << "WriteFDSameAsSocketId DONE\n";
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
	X2	mark;
	std::cerr << "SetNonBlockingFails\n";
    TA_TestThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorSetSocketNonBlocking).inject().toReturn(-1)
    .run();
	std::cerr << "SetNonBlockingFails DONE\n";
}

TEST(ConnectionSocketTest, ShutdownFails)
{
	X2	mark;
	std::cerr << "ShutdownFails\n";
    TA_TestNoThrow([](){
        SocketClient                socket({"github.com",80}, Blocking::No);
        socket.tryFlushBuffer();
    })
    .expectObjectTA(Socket_NonBlocking)
        .expectCallTA(thorShutdownSocket).toReturn(0)
    .run();
	std::cerr << "ShutdownFails DONE\n";
}
