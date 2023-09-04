#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionFileTest.h"


#include <unistd.h>
#include <stdlib.h>

using ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::BuildTools::Mock::MockActionThrowDetext;
using ThorsAnvil::BuildTools::Mock::MockActionAddObject;
using ThorsAnvil::BuildTools::Mock::MockAction;

TEST(ConnectionFileTest, Construct)
{
    MockConnectionFile          defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkFile(defaultMockedFunctions, MockConnectionFile::getActionFile());
        File                        file("TestFile", Open::Append, Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionFileTest, ConstructOpenFail)
{
    MockConnectionFile          defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(OpenType, open, [](const char*, int, unsigned short)    {return -1;});

    auto action = [&](){
        MockActionAddObject         checkFile(defaultMockedFunctions, MockConnectionFile::getActionFile());
        File                        file("TestFile", Open::Append, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action(),
        std::runtime_error
    );
}

TEST(ConnectionFileTest, notValidOnMinusOne)
{
    MockConnectionFile          defaultMockedFunctions;
    File                        file(-1);

    auto action = [&](){
        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionFileTest, getSocketIdWorks)
{
    MockConnectionFile          defaultMockedFunctions;
    File                        file(12);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionFileTest, Close)
{
    MockConnectionFile          defaultMockedFunctions;
    File                        file("TestFile", Open::Append, Blocking::No);

    auto action = [&](){
        MockActionAddObject         checkClose(defaultMockedFunctions, MockAction{"Close", {"close"}, {}, {}, {}});
        file.close();
        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionFileTest, ReadFDSameAsSocketId)
{
    MockConnectionFile          defaultMockedFunctions;
    File                        file(33);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}

TEST(ConnectionFileTest, WriteFDSameAsSocketId)
{
    MockConnectionFile          defaultMockedFunctions;
    File                        file(34);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect(defaultMockedFunctions);action()
    );
}
