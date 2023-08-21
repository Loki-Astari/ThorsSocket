#include <gtest/gtest.h>
#include "ConnectionPipe.h"

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
    int callCount = 0;
    MOCK_SYS(pipe, [](int fd[])    {return -1;});
    MOCK_SYS(close,[&callCount](int)    {++callCount;return 0;});

    auto action = [](){
        Pipe                        pipe(Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(callCount, 0);
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFail)
{
    int callCount = 0;
    int fctlCalled = 0;
    MOCK_SYS(pipe, [](int fd[])         {return 0;});
    MOCK_SYS(close,[&callCount](int)    {++callCount;return 0;});
    MOCK_TSYS(FctlType, fcntl,[&fctlCalled] (int, int, int)         {return -1;});

    auto action = [](){
        Pipe                        pipe(Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(callCount, 2);
}

TEST(ConnectionPipeTest, DestructorCallsClose)
{
    int callCount = 0;
    MOCK_SYS(pipe, [](int fd[])           {fd[0]=12;fd[1]=13;return 0;});
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    {
        Pipe                    pipe(Blocking::Yes);
    }


    ASSERT_EQ(callCount, 2);
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    int fd[] = {-1, -1};
    Pipe                        pipe(fd);
    ASSERT_FALSE(pipe.isConnected());
}

TEST(ConnectionPipeTest, getSocketIdWorks)
{
    int fd[] = {12, 13};
    Pipe                        pipe(fd);
    ASSERT_EQ(pipe.socketId(Mode::Read), 12);
    ASSERT_EQ(pipe.socketId(Mode::Write), 13);
}

TEST(ConnectionPipeTest, Close)
{
    Pipe                        pipe(Blocking::No);
    pipe.close();

    ASSERT_FALSE(pipe.isConnected());
}

TEST(ConnectionPipeTest, ReadFDSameAsSocketId)
{
    int fd[] = {33, 34};
    Pipe                        pipe(fd);
    ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
}

TEST(ConnectionPipeTest, WriteFDSameAsSocketId)
{
    int fd[] = {33, 34};
    Pipe                        pipe(fd);
    ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
}
