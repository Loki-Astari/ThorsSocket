#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/MockDefaultThorsSocket.h"


#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::File;
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

TA_Object   File(
                build()
                .expectInitTA(open).toReturn(0)
                .expectDestTA(close)
            );
}

TEST(TAConnectionFileTest, Construct)
{
    TA_TestNoThrow([](){
        File                        file("TestFile", Open::Append, Blocking::No);
    })
    .expectObjectTA(File)
    .run();
}

TEST(TAConnectionFileTest, ConstructOpenFail)
{
    TA_TestThrow([](){
        File                        file("TestFile", Open::Append, Blocking::No);
    })
    .expectObjectTA(File)
        .errorInitTA(open).toReturn(-1)
    .run();
}

TEST(TAConnectionFileTest, notValidOnMinusOne)
{
    TA_TestNoThrow([](){
        File                        file(-1);
        ASSERT_FALSE(file.isConnected());
    })
    .run();
}

TEST(TAConnectionFileTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(12);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    })
    .run();
}

TEST(TAConnectionFileTest, Close)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file("TestFile", Open::Append, Blocking::No);

    TA_TestNoThrow([&](){
        file.close();
        ASSERT_FALSE(file.isConnected());
    })
    .expectCodeTA(close)
    .run();
}

TEST(TAConnectionFileTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(33);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    })
    .run();
}

TEST(TAConnectionFileTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(34);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    })
    .run();
}
