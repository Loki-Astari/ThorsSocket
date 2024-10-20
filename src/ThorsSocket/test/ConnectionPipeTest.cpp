#include <gtest/gtest.h>
#include "ConnectionPipe.h"

#include <iostream>
struct Mark
{
    Mark() {std::cerr << "Mark\n";}
    ~Mark(){std::cerr << "Mark Done\n";}
};

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
                .expectInitTA(thorCreatePipe).toReturn(0)
                .optionalTA(thorSetFDNonBlocking).toReturn(0)
                .expectDestTA(close)
                .expectDestTA(close)
            );
}

TEST(ConnectionPipeTest, Construct)
{
    Mark  marker;
    TA_TestNoThrow([](){
        Pipe                        pipe({}, Blocking::No);
    })
    .expectObjectTA(Pipe)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeFail)
{
    Mark  marker;
    TA_TestThrow([](){
        Pipe                        pipe({},Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(thorCreatePipe).inject().toReturn(-1)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFailFirst)
{
    Mark  marker;
    TA_TestThrow([](){
        Pipe                        pipe({},Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(thorSetFDNonBlocking).inject().toReturn(-1)
        .expectCallTA(close).toReturn(0)
        .expectCallTA(close).toReturn(0)
    .run();
}

TEST(ConnectionPipeTest, ConstructPipeNonBlockingFailSecond)
{
    Mark  marker;
    TA_TestThrow([](){
        Pipe                        pipe({},Blocking::No);
    })
    .expectObjectTA(Pipe)
        .expectCallTA(thorSetFDNonBlocking).inject().toReturn(0)
        .expectCallTA(thorSetFDNonBlocking).inject().toReturn(-1)
        .expectCallTA(close).toReturn(0)
        .expectCallTA(close).toReturn(0)
    .run();
}

TEST(ConnectionPipeTest, notValidOnMinusOne)
{
    Mark  marker;
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
    Mark  marker;
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
    Mark  marker;
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    // see ConnectionUtil.cpp
    GTEST_SKIP();
#endif
    MockAllDefaultFunctions     defaultMockedFunctions;
    Pipe                        pipe({},Blocking::No);

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
    Mark  marker;
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
    Mark  marker;
    MockAllDefaultFunctions     defaultMockedFunctions;
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);

    TA_TestNoThrow([&](){
        ASSERT_EQ(pipe.socketId(Mode::Write), pipe.getWriteFD());
    })
    .run();
}

TEST(ConnectionPipeTest, Protocol)
{
    int                         fd[] = {33, 34};
    Pipe                        pipe(fd);
    EXPECT_EQ("pipe", pipe.protocol());
}
    
