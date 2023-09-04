#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "test/ConnectionSocketTest.h"
#include "test/ConnectionTest.h"

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;
using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock::MockActionAddCode;
using ThorsAnvil::BuildTools::Mock::MockAction;

TEST(ConnectionSocketTest, Construct)
{
    MockConnectionSocket        defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com",80 , Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    MockConnectionSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(socket, [&](int, int, int)    {defaultMockedFunctions.checkExpected("socket");return -1;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    h_errno = NO_DATA;

    // Override default behavior
    MOCK_SYS(gethostbyname, [&](char const*)     {defaultMockedFunctions.checkExpected("gethostbyname");h_errno = HOST_NOT_FOUND;return nullptr;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
    MockConnectionSocket          defaultMockedFunctions;
    h_errno = NO_DATA;

    // Override default behavior
    MOCK_SYS(gethostbyname, [&](char const*)     {defaultMockedFunctions.checkExpected("gethostbyname");static int call =0; ++call; h_errno = (call == 1) ? TRY_AGAIN : HOST_NOT_FOUND; return nullptr;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking(), {"gethostbyname", "close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    MockConnectionSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(connect,   [&](int, SocketAddr const*, unsigned int) {defaultMockedFunctions.checkExpected("connect");return -1;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    MockConnectionSocket          defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketBlocking());
        Socket                      socket("github.com", 80, Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    MockConnectionSocket          defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                        socket(-1);

    auto action = [&]() {
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                        socket(12);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, Close)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                      socket("github.com",80 , Blocking::No);

    auto action = [&](){
        MockActionAddObject     checkClose(defaultMockedFunctions, MockAction{"Close", {"close"}, {}, {}, {}});
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                        socket(33);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                        socket(34);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(FctlType, fcntl,  [&](int, int, int){defaultMockedFunctions.checkExpected("fcntl");return -1;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("google.com", 80, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    // Override default behavior
    MOCK_SYS(shutdown,  [&](int, int)    {defaultMockedFunctions.checkExpected("shutdown");return -1;});

    auto action = [&](){
        MockActionAddObject         checkSokcet(defaultMockedFunctions, MockConnectionSocket::getActionSocketNonBlocking());
        Socket                      socket("google.com", 80, Blocking::No);

        MockActionAddCode           checkShutdown(defaultMockedFunctions, MockAction{"shutdown", {"shutdown"}, {}, {}, {}});
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}
