#include <gtest/gtest.h>
#include "ConnectionFile.h"

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
using ThorsAnvil::ThorsSocket::Type;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;

TEST(ConnectionFileTest, Construct)
{
    TempFileWithCleanup         fileName;
    File                        file(fileName,Type::Append, Blocking::No);
}

TEST(ConnectionFileTest, ConstructOpenFail)
{
    using OpenType = int(const char*, int, unsigned short);
    MOCK_TSYS(OpenType, open, [](const char*, int, unsigned short)    {return -1;});
    TempFileWithCleanup         fileName;

    auto action = [&fileName](){
        File                        file(fileName,Type::Append, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionFileTest, DestructorCallsClose)
{
    int callCount = 0;
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    {
        TempFileWithCleanup     fileName;
        File                    file(12);
    }


    ASSERT_EQ(callCount, 1);
}

TEST(ConnectionFileTest, notValidOnMinusOne)
{
    File                        file(-1);
    ASSERT_FALSE(file.isConnected());
}

TEST(ConnectionFileTest, getSocketIdWorks)
{
    File                        file(12);
    ASSERT_EQ(file.socketId(), 12);
}

TEST(ConnectionFileTest, Close)
{
    TempFileWithCleanup         fileName;
    File                        file(fileName,Type::Append, Blocking::No);
    file.close();

    ASSERT_FALSE(file.isConnected());
}

TEST(ConnectionFileTest, ReadFDSameAsSocketId)
{
    File                        file(33);
    ASSERT_EQ(file.socketId(), file.getReadFD());
}

TEST(ConnectionFileTest, WriteFDSameAsSocketId)
{
    File                        file(34);
    ASSERT_EQ(file.socketId(), file.getWriteFD());
}
