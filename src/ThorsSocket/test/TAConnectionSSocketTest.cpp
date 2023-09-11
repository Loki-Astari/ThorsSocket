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

TEST(TAConnectionFileTest, Construct)
{
    MockDefaultThorsSocket          defaultMockedFunctions;

    auto action = [&](){
        MockActionAddObject         checkFile(MockDefaultThorsSocket::getActionFile());
        File                        file("TestFile", Open::Append, Blocking::No);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionFileTest, ConstructOpenFail)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    // Override default behavior
    MOCK_TSYS(OpenType, open, [](const char*, int, unsigned short)    {return -1;});

    auto action = [](){
        MockActionAddObject         checkFile(MockDefaultThorsSocket::getActionFile());
        File                        file("TestFile", Open::Append, Blocking::No);
    };
    ASSERT_THROW(
        MockActionThrowDetext detect;action(),
        std::runtime_error
    );
}

TEST(TAConnectionFileTest, notValidOnMinusOne)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(-1);

    auto action = [&](){
        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionFileTest, getSocketIdWorks)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(12);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionFileTest, Close)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file("TestFile", Open::Append, Blocking::No);

    auto action = [&](){
        MockActionAddObject         checkClose(MockAction{"Close", {"close"}, {}, {}, {}});
        file.close();
        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionFileTest, ReadFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(33);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}

TEST(TAConnectionFileTest, WriteFDSameAsSocketId)
{
    MockDefaultThorsSocket      defaultMockedFunctions;
    File                        file(34);

    auto action = [&](){
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    };
    ASSERT_NO_THROW(
        MockActionThrowDetext detect;action()
    );
}
