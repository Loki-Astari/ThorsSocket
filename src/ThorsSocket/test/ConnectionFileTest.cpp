#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionFileTest.h"


#include <unistd.h>
#include <stdlib.h>

class TempFileWithCleanup
{
    std::string     fileName;
    public:
        TempFileWithCleanup()
            : fileName("/var/tmp/XXXXXX")
        {
            mktemp(fileName.data());
        }
        ~TempFileWithCleanup()
        {
            unlink(fileName.c_str());
        }
        operator std::string const&() {return fileName;}
};

using ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;

TEST(ConnectionFileTest, Construct)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        TempFileWithCleanup         fileName;
        File                        file(fileName,Open::Append, Blocking::No);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionFileTest, ConstructOpenFail)
{
    MockConnectionFile          defaultMockedFunctions;
    using OpenType = int(const char*, int, unsigned short);
    MOCK_TSYS(OpenType, open, [](const char*, int, unsigned short)    {return -1;});
    TempFileWithCleanup         fileName;

    auto action = [&fileName](){
        File                        file(fileName,Open::Append, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionFileTest, DestructorCallsClose)
{
    MockConnectionFile          defaultMockedFunctions;
    int callCount = 0;
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});


    auto action = [](){
        TempFileWithCleanup     fileName;
        File                    file(12);
    };
    ASSERT_NO_THROW(
        action()
    );


    ASSERT_EQ(callCount, 1);
}

TEST(ConnectionFileTest, notValidOnMinusOne)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close, [](int)    {return 0;});

    auto action = [](){
        File                        file(-1);
        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionFileTest, getSocketIdWorks)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close, [](int)    {return 0;});

    auto action = [](){
        File                        file(12);
        ASSERT_EQ(file.socketId(Mode::Read), 12);
        ASSERT_EQ(file.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionFileTest, Close)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close, [](int)    {return 0;});

    auto action = [](){
        TempFileWithCleanup         fileName;
        File                        file(fileName,Open::Append, Blocking::No);
        file.close();

        ASSERT_FALSE(file.isConnected());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionFileTest, ReadFDSameAsSocketId)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close, [](int)    {return 0;});

    auto action = [](){
        File                        file(33);
        ASSERT_EQ(file.socketId(Mode::Read), file.getReadFD());
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(ConnectionFileTest, WriteFDSameAsSocketId)
{
    MockConnectionFile          defaultMockedFunctions;
    MOCK_SYS(close, [](int)    {return 0;});

    auto action = [](){
        File                        file(34);
        ASSERT_EQ(file.socketId(Mode::Write), file.getWriteFD());
    };
    ASSERT_NO_THROW(
        action()
    );
}
