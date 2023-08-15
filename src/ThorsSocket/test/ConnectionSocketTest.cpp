#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "test/ConnectionTest.h"

using ThorsAnvil::ThorsSocket::ConnectionType::Socket;

TEST(ConnectionSocketTest, Construct)
{
    Socket                      socket("github.com",80 , Blocking::No);
}

TEST(ConnectionSocketTest, ConstructOpenFail)
{
    using OpenType = int(const char*, int, unsigned short);
    MOCK_TSYS(OpenType, open, [](const char*, int, unsigned short)    {return -1;});
    Socket                      socket("github.com",80 , Blocking::No);

    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSocketTest, DestructorCallsClose)
{
    int callCount = 0;
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    Socket                      socket(12);
    ASSERT_EQ(callCount, 1);
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    Socket                      socket(-1);
    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    Socket                      socket(12);
    ASSERT_EQ(socket.socketId(), 12);
}

TEST(ConnectionSocketTest, Close)
{
    Socket                      socket("github.com",80 , Blocking::No);
    socket.close();

    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
    Socket                      socket(33);
    ASSERT_EQ(socket.socketId(), socket.getReadFD());
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
    Socket                      socket(34);
    ASSERT_EQ(socket.socketId(), socket.getWriteFD());
}
