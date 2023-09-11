#include <gtest/gtest.h>
#include "ConnectionPipe.h"
#include "test/MockDefaultThorsSocket.h"

#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::Pipe;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::BuildTools::Mock1::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock1::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock1::MockAction;

TEST(ConnectionPipeTest, Construct)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [](){
        MockActionAddObject         checkPipe(MockDefaultThorsSocket::getActionPipeNonBlocking());
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionPipeTest, ConstructPipeFail)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    // Override default behavior
    MOCK_SYS(pipe, [](int[])            {return -1;});

    auto action = [](){
        MockActionAddObject         checkPipe(MockDefaultThorsSocket::getActionPipeNonBlocking());
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFail)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(FctlType, fcntl,  [](int, int, int)     {return -1;});

    auto action = [](){
        MockActionAddObject         checkPipe(MockDefaultThorsSocket::getActionPipeNonBlocking(), {"close"});
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {-1, -1};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionPipeTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {12, 13};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), 12);
        ASSERT_EQ(pipe.socketId(Mode::Write), 13);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionPipeTest, Close)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    Pipe                        pipe(Blocking::No);

    auto action = [&](){
        MockActionAddObject         checkClose(MockAction{"Close", {"close", "close"}, {}, {}, {}});
        pipe.close();

        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionPipeTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(ConnectionPipeTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}
