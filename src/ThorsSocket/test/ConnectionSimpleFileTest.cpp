#include <gtest/gtest.h>
#include "ConnectionSimpleFile.h"

#include <iostream>
struct Mark
{
    Mark() {std::cerr << "Mark\n";}
    ~Mark(){std::cerr << "Mark Done\n";}
};

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
    Mark  marker;
    TA_TestNoThrow([](){
        SimpleFile                        file({"TestFile", Open::Append}, Blocking::No);
    })
    .expectObjectTA(File)
    .run();
}

TEST(ConnectionFileTest, ConstructOpenFail)
{
    Mark  marker;
    TA_TestThrow([](){
        SimpleFile                        file({"TestFile", Open::Append}, Blocking::No);
    })
    .expectObjectTA(File)
        .expectCallTA(open).inject().toReturn(-1)
    .run();
}

TEST(ConnectionFileTest, notValidOnMinusOne)
{
    Mark  marker;
    TA_TestNoThrow([](){
        SimpleFile                        file(-1);
        ASSERT_FALSE(file.isConnected());
    })
    .run();
}

TEST(ConnectionFileTest, getSocketIdWorks)
{
    Mark  marker;
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
    Mark  marker;
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file({"TestFile", Open::Append}, Blocking::No);

    TA_TestNoThrow([&](){
        file.close();
        ASSERT_FALSE(file.isConnected());
    })
    .expectCallTA(close)
    .run();
}

TEST(ConnectionFileTest, ReadFDSameAsSocketId)
{
    Mark  marker;
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(33);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    })
    .run();
}

TEST(ConnectionFileTest, WriteFDSameAsSocketId)
{
    Mark  marker;
    MockAllDefaultFunctions     defaultMockedFunctions;
    SimpleFile                  file(34);

    TA_TestNoThrow([&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    })
    .run();
}

TEST(ConnectionFileTest, Protocol)
{
    SimpleFile                  file(34);
    EXPECT_EQ("file", file.protocol());
}
