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
using ThorsAnvil::BuildTools::Mock1::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock1::TA_TestNoThrow;

namespace ThorsAnvil::BuildTools::Mock1
{
TA_Object   Pipe(
                build()
                .expectInitTA(pipe).toReturn(0)
                .optionalTA(fcntl).toReturn(0)
                .expectDestTA(close)
                .expectDestTA(close)
            );
}

TEST(TAConnectionPipeTest, Construct)
{
    TA_TestNoThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
    .run();
}

TEST(TAConnectionPipeTest, ConstructPipeFail)
{
    TA_TestThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
        .errorInitTA(pipe).toReturn(-1)
    .run();
}

TEST(TAConnectionPipeTest, ConstructPipeNonBlockingFail)
{
    TA_TestThrow([](){
        Pipe                        pipe(Blocking::No);
    })
    .expectObjectTA(Pipe)
        .errorInitTA(fcntl).toReturn(-1)
        .errorTA(fcntl).toReturn(0)
        .errorTA(close).toReturn(0)
        .errorTA(close).toReturn(0)
    .run();
}

TEST(TAConnectionPipeTest, notValidOnMinusOne)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {-1, -1};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_FALSE(pipe.isConnected());
    })
    .run();
}

TEST(TAConnectionPipeTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {12, 13};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), 12);
        ASSERT_EQ(pipe.socketId(Mode::Write), 13);
    })
    .run();
}

TEST(TAConnectionPipeTest, Close)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    Pipe                        pipe(Blocking::No);

    TA_TestNoThrow([&](){
        pipe.close();
        ASSERT_FALSE(pipe.isConnected());
    })
    .expectCodeTA(close)
    .codeTA(close)
    .run();
}

TEST(TAConnectionPipeTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Read), pipe.getReadFD());
    })
    .run();
}

TEST(TAConnectionPipeTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    })
    .run();
}
