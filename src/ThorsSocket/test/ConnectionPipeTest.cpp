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

TEST(ConnectionPipeTest, Construct)
{
    Pipe                        pipe(Blocking::No);
}

TEST(ConnectionPipeTest, ConstructPipeFail)
{
    MockConnectionPipe          defaultMockedFunctions;
    int callCount = 0;
    MOCK_SYS(pipe, [](int[])            {return -1;});

    auto action = [](){
        Pipe                        pipe(Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFail)
{
    MockConnectionPipe          defaultMockedFunctions;
    int pipeCount = 0;
    int closeCount = 0;
    int fctlCount = 0;
    MOCK_SYS(pipe,              [&](int*)               {++pipeCount;return 0;});
    MOCK_SYS(close,             [&](int)                {++closeCount;return 0;});
    MOCK_TSYS(FctlType, fcntl,  [&] (int, int, int)     {++fctlCount;return -1;});

    auto action = [](){
        Pipe                        pipe(Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(pipeCount, 1);
    ASSERT_EQ(closeCount, 2);
    ASSERT_EQ(fctlCount, 2);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, DestructorCallsClose)
{
    MockConnectionPipe          defaultMockedFunctions;
    int callCount = 0;
    MOCK_SYS(pipe, [](int fd[])           {fd[0]=12;fd[1]=13;return 0;});
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    auto action = [](){
        Pipe                    pipe(Blocking::Yes);
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(callCount, 2);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    MockConnectionPipe          defaultMockedFunctions;

    auto action = [](){
        int fd[] = {-1, -1};
        Pipe                        pipe(fd);
        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, getSocketIdWorks)
{
    MockConnectionPipe          defaultMockedFunctions;
    MOCK_SYS(close,         [](int) {return 0;});

    auto action = [](){
        int fd[] = {12, 13};
        Pipe                        pipe(fd);
        ASSERT_EQ(pipe.socketId(Mode::Read), 12);
        ASSERT_EQ(pipe.socketId(Mode::Write), 13);
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, Close)
{
    MockConnectionPipe          defaultMockedFunctions;
    int pipeCount = 0;
    int closeCount = 0;
    int fctlCount = 0;
    MOCK_SYS(pipe,              [&](int*)               {++pipeCount;return 0;});
    MOCK_SYS(close,             [&](int)                {++closeCount;return 0;});
    MOCK_TSYS(FctlType, fcntl,  [&] (int, int, int)     {++fctlCount;return 0;});

    auto action = [](){
        Pipe                        pipe(Blocking::No);
        pipe.close();

        ASSERT_FALSE(pipe.isConnected());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(pipeCount, 1);
    ASSERT_EQ(closeCount, 2);
    ASSERT_EQ(fctlCount, 2);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, ReadFDSameAsSocketId)
{
    MockConnectionPipe          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        int fd[] = {33, 34};
        Pipe                        pipe(fd);
        ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionPipeTest, WriteFDSameAsSocketId)
{
    MockConnectionPipe          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        int fd[] = {33, 34};
        Pipe                        pipe(fd);
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}
