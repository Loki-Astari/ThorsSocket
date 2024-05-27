#include <gtest/gtest.h>
#include "ConnectionPipe.h"

#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::Pipe;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;

namespace ThorsAnvil::BuildTools::Mock
{
TA_Object   Pipe(
                build()
                .expectInitTA(pipe).toReturn(0)
                .optionalTA(fcntl).toReturn(0)
                .expectDestTA(close)
                .expectDestTA(close)
            );
}

TEST(ConnectionPipeTest, Construct)
{
    TA_TestNoThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeFail)
{
    TA_TestThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(pipe).inject().toReturn(-1)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFailFirst)
{
    TA_TestThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(fcntl).inject().toReturn(-1)
        .expectCallTA(close).toReturn(0)
        .expectCallTA(close).toReturn(0)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFailSecond)
{
    TA_TestThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(fcntl).inject().toReturn(0)
        .expectCallTA(fcntl).inject().toReturn(-1)
        .expectCallTA(close).toReturn(0)
        .expectCallTA(close).toReturn(0)
    .run();
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    int                         fd[] = {-1, -1};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_FALSE(pipe.isConnected());
    })
    .run();
}

TEST(ConnectionPipeTest, getSocketIdWorks)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    int                         fd[] = {12, 13};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), 12);
        ASSERT_EQ(pipe.socketId(Mode::Write), 13);
    })
    .run();
}

TEST(ConnectionPipeTest, Close)
{
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    .. see ConnectionWrapper.cpp
    GTEST_SKIP();
#endif
    MockAllDefaultFunctions     defaultMockedFunctions;
    Pipe                        pipe(Blocking::No);

    TA_TestNoThrow([&](){
        pipe.close();
        ASSERT_FALSE(pipe.isConnected());
    })
    .expectCallTA(close)
    .expectCallTA(close)
    .run();
}

TEST(ConnectionPipeTest, ReadFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
    })
    .run();
}

TEST(ConnectionPipeTest, WriteFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    })
    .run();
}
