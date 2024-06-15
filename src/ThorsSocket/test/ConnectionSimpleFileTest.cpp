#include <gtest/gtest.h>
#include "ConnectionSimpleFile.h"

#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::SimpleFile;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;

namespace ThorsAnvil::BuildTools::Mock
{

TA_Object   File(
                build()
                .expectInitTA(open).toReturn(0)
                .expectDestTA(close)
            );
}

TEST(ConnectionFileTest, Construct)
{
    TA_TestNoThrow([](){
        SimpleFile                        file("TestFile", Open::Append, Blocking::No);
    })
    .expectObjectTA(File)
    .run();
}

TEST(ConnectionFileTest, ConstructOpenFail)
{
    TA_TestThrow([](){
        SimpleFile                        file("TestFile", Open::Append, Blocking::No);
    })
    .expectObjectTA(File)
        .expectCallTA(open).inject().toReturn(-1)
    .run();
}

TEST(ConnectionFileTest, notValidOnMinusOne)
{
    TA_TestNoThrow([](){
        SimpleFile                        file(-1);
        ASSERT_FALSE(file.isConnected());
    })
    .run();
}

TEST(ConnectionFileTest, getSocketIdWorks)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(12);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    })
    .run();
}

TEST(ConnectionFileTest, Close)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file("TestFile", Open::Append, Blocking::No);

    TA_TestNoThrow([&](){
        file.close();
        ASSERT_FALSE(file.isConnected());
    })
    .expectCallTA(close)
    .run();
}

TEST(ConnectionFileTest, ReadFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(33);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    })
    .run();
}

TEST(ConnectionFileTest, WriteFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(34);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    })
    .run();
}
