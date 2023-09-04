#include <gtest/gtest.h>
#include "ConnectionPipe.h"
#include "test/ConnectionPipeTest.h"

#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::Pipe;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock::MockAction;

TEST(ConnectionPipeTest, Construct)
{
    MockConnectionPipe          defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkPipe(defaultMockedFunctions, MockConnectionPipe::getActionPipeNonBlocking());
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionPipeTest, ConstructPipeFail)
{
    MockConnectionPipe          defaultMockedFunctions;
    // Override default behavior
    MOCK_SYS(pipe, [&](int[])            {defaultMockedFunctions.checkExpected("pipe");return -1;});

    auto action = [&](){
        MockActionAddObject         checkPipe(defaultMockedFunctions, MockConnectionPipe::getActionPipeNonBlocking());
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFail)
{
    MockConnectionPipe          defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(FctlType, fcntl,  [&](int, int, int)     {defaultMockedFunctions.checkExpected("fcntl");return -1;});

    auto action = [&](){
        MockActionAddObject         checkPipe(defaultMockedFunctions, MockConnectionPipe::getActionPipeNonBlocking(), {"close"});
        Pipe                        pipe(Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    MockConnectionPipe          defaultMockedFunctions;
    int                         fd[] = {-1, -1};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionPipeTest, getSocketIdWorks)
{
    MockConnectionPipe          defaultMockedFunctions;
    int                         fd[] = {12, 13};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), 12);
        ASSERT_EQ(pipe.socketId(Mode::Write), 13);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionPipeTest, Close)
{
    MockConnectionPipe          defaultMockedFunctions;
    Pipe                        pipe(Blocking::No);

    auto action = [&](){
        MockActionAddObject         checkClose(defaultMockedFunctions, MockAction{"Close", {"close", "close"}, {}, {}, {}});
        pipe.close();

        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionPipeTest, ReadFDSameAsSocketId)
{
    MockConnectionPipe          defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionPipeTest, WriteFDSameAsSocketId)
{
    MockConnectionPipe          defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    auto action = [&](){
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}
