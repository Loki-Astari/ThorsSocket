#include <gtest/gtest.h>
#include "ConnectionSimpleFile.h"

#include <iostream>

using ThorsAnvil::ThorsSocket::ConnectionType::SimpleFile;
using ThorsAnvil::ThorsSocket::FileMode;
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

TEST(ConnectionSimpleFileTest, Construct)
{
    TA_TestNoThrow([](){
        SimpleFile                        file({"TestFile", FileMode::WriteAppend}, Blocking::No);
        EXPECT_TRUE(file.isConnected());
    })
    .expectObjectTA(File)
    .run();
}

TEST(ConnectionSimpleFileTest, ConstructOpenFail)
{
    TA_TestNoThrow([](){
        SimpleFile                        file({"TestFile", FileMode::WriteAppend}, Blocking::No);
        EXPECT_TRUE(file.isConnected());
    })
    .expectObjectTA(File)
    .run();
}

TEST(ConnectionSimpleFileTest, notValidOnMinusOne)
{
    TA_TestNoThrow([](){
        SimpleFile                        file(-1);
        ASSERT_FALSE(file.isConnected());
    })
    .run();
}

TEST(ConnectionSimpleFileTest, getSocketIdWorks)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(12);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    })
    .run();
}

TEST(ConnectionSimpleFileTest, Close)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file({"TestFile", FileMode::WriteAppend}, Blocking::No);

    TA_TestNoThrow([&](){
        file.close();
        ASSERT_FALSE(file.isConnected());
    })
    .expectCallTA(close)
    .run();
}

TEST(ConnectionSimpleFileTest, ReadFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(33);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    })
    .run();
}

TEST(ConnectionSimpleFileTest, WriteFDSameAsSocketId)
{
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(34);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    })
    .run();
}

TEST(ConnectionSimpleFileTest, Protocol)
{
    SimpleFile                  file(34);
    EXPECT_EQ("file", file.protocol());
}
