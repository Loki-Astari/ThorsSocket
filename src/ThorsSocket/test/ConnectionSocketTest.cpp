#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;
using ThorsAnvil::BuildTools::Mock1::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock1::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock1::MockActionAddCode;
using ThorsAnvil::BuildTools::Mock1::MockAction;

TEST(ConnectionSocketTest, Construct)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com",80 , Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(socket, [](int, int, int)    {return -1;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    h_errno = NO_DATA;

    // Override default behavior
    MOCK_SYS(gethostbyname, [](char const*)     {h_errno = HOST_NOT_FOUND;return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    h_errno = NO_DATA;

    // Override default behavior
    MOCK_SYS(gethostbyname, [](char const*)     {static int call =0; ++call; h_errno = (call == 1) ? TRY_AGAIN : HOST_NOT_FOUND; return nullptr;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking(), {"gethostbyname", "close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    // Override default behavior
    MOCK_SYS(connect,   [](int, SocketAddr const*, unsigned int) {return -1;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketBlocking());
        Socket                      socket("github.com", 80, Blocking::Yes);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking());
        Socket                      socket("github.com", 80, Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    Socket                        socket(-1);

    auto action = [&]() {
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    Socket                        socket(12);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, Close)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    Socket                      socket("github.com",80 , Blocking::No);

    auto action = [&](){
        MockActionAddObject     checkClose(MockAction{"Close", {"close"}, {}, {}, {}});
        socket.close();
        ASSERT_FALSE(socket.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    Socket                        socket(33);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    Socket                        socket(34);

    auto action = [&](){
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(FctlType, fcntl,  [](int, int, int){return -1;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking(), {"close"});
        Socket                      socket("google.com", 80, Blocking::No);
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    MockDefaultThorsSocket        defaultMockedFunctions;
    // Override default behavior
    MOCK_SYS(shutdown,  [](int, int)    {return -1;});

    auto action = [](){
        MockActionAddObject         checkSokcet(MockDefaultThorsSocket::getActionSocketNonBlocking());
        Socket                      socket("google.com", 80, Blocking::No);

        MockActionAddCode           checkShutdown(MockAction{"shutdown", {"shutdown"}, {}, {}, {}});
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}
