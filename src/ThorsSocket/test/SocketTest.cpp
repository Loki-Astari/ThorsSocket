#include "test/pipe.h"
#include "Socket.h"
#include "ConnectionNormal.h"
#include "ConnectionSSL.h"
#include "ThorsLogging/ThorsLogging.h"
#include "coverage/ThorMock.h"
#include <fstream>
#include <gtest/gtest.h>
#include <future>
#include <unistd.h>
#include <fcntl.h>

using ThorsAnvil::ThorsSocket::BaseSocket;
using ThorsAnvil::ThorsSocket::DataSocket;
using ThorsAnvil::ThorsSocket::ConnectSocketNormal;
using ThorsAnvil::ThorsSocket::ServerSocketNormal;
using ThorsAnvil::ThorsSocket::ConnectionNormal;
//using ThorsAnvil::ThorsSocket::SSLServerSocket;
using ThorsAnvil::ThorsSocket::SSLMethod;
using ThorsAnvil::ThorsSocket::SSLctx;;
using ReadInfo = std::pair<bool, std::size_t>;

static ThorsAnvil::ThorsSocket::ConnectionBuilder getNormalBuilder()
{
    return [](int fd){return std::make_unique<ConnectionNormal>(fd);};
}

class DerivedFromBase: public BaseSocket
{
    public:
        DerivedFromBase()
            : BaseSocket()
        {}
        DerivedFromBase(int socketId, bool blocking = true)
            : BaseSocket(socketId, blocking)
        {}
};

TEST(SocketTest, defaultConstruct)
{
    DerivedFromBase     derived;
}
TEST(SocketTest, baseSocketInitNonBlocking)
{
    SocketSetUp     setupSocket;

    int sock = ::socket(PF_INET, SOCK_STREAM, 0);
    DerivedFromBase     derived(sock, false);
}
TEST(SocketTest, baseSocketInitBlocking)
{
    SocketSetUp     setupSocket;

    int sock = ::socket(PF_INET, SOCK_STREAM, 0);
    DerivedFromBase     derived(sock, true);
}
TEST(SocketTest, baseSocketMoveConstruct)
{
    SocketSetUp     setupSocket;

    int sock = ::socket(PF_INET, SOCK_STREAM, 0);
    DerivedFromBase     derived1(sock);
    DerivedFromBase     derived2(std::move(derived1));

    EXPECT_EQ(-1,    derived1.getSocketId());
    EXPECT_EQ(sock,  derived2.getSocketId());
}
TEST(SocketTest, baseSocketMoveAssign)
{
    SocketSetUp     setupSocket;

    int sock1 = ::socket(PF_INET, SOCK_STREAM, 0);
    int sock2 = ::socket(PF_INET, SOCK_STREAM, 0);
    DerivedFromBase     derived1(sock1);
    DerivedFromBase     derived2(sock2);

    derived2 = std::move(derived1);

    EXPECT_EQ(sock1, derived2.getSocketId());
}
TEST(SocketTest, baseSocketSwap)
{
    SocketSetUp     setupSocket;

    int sock1 = ::socket(PF_INET, SOCK_STREAM, 0);
    int sock2 = ::socket(PF_INET, SOCK_STREAM, 0);
    DerivedFromBase     derived1(sock1);
    DerivedFromBase     derived2(sock2);

    using std::swap;
    swap(derived1, derived2);

    EXPECT_EQ(sock1,  derived2.getSocketId());
    EXPECT_EQ(sock2,  derived1.getSocketId());
}
TEST(SocketTest, ConnectSocket)
{
    SocketSetUp     setupSocket;

    ConnectSocketNormal   socket("amazon.com", 80);
}
TEST(SocketTest, ServerSocketAccept)
{
    SocketSetUp     setupSocket;

    ServerSocketNormal    socket(12345678, true);
    auto future = std::async( std::launch::async, [](){ConnectSocketNormal connect("127.0.0.1", 12345678);});
    DataSocket      connection = socket.accept();

    ASSERT_NE(-1, connection.getSocketId());
}
TEST(SocketTest, readOneLine)
{
    SocketSetUp     setupSocket;

    int fd[2];
    std::string const testData    = "A line of text\n";
    EXPECT_EQ(0, CREATE_PIPE(fd));
    EXPECT_EQ(testData.size(), ::write(fd[1], testData.c_str(), testData.size()));
    EXPECT_EQ(0, ::close(fd[1]));

    DataSocket      pipeReader(getNormalBuilder(), fd[0]);
    std::string     buffer(testData.size(), '\0');
    ReadInfo read = pipeReader.getMessageData(&buffer[0], testData.size());
    ASSERT_EQ(true, read.first);
    ASSERT_EQ(testData.size(), read.second);
    EXPECT_EQ(testData, buffer);
}
TEST(SocketTest, readMoreDataThanIsAvailable)
{
    SocketSetUp     setupSocket;

    int fd[2];
    std::string const testData    = "A line of text\n";
    EXPECT_EQ(0, CREATE_PIPE(fd));
    EXPECT_EQ(testData.size(), ::write(fd[1], testData.c_str(), testData.size()));
    EXPECT_EQ(0, ::close(fd[1]));

    DataSocket      pipeReader(getNormalBuilder(), fd[0]);
    std::string     buffer(testData.size() + 10, '\0');
    ReadInfo read = pipeReader.getMessageData(&buffer[0], testData.size() + 10);
    EXPECT_EQ(false, read.first);
    EXPECT_EQ(testData.size(), read.second);
    buffer.resize(read.second);
    EXPECT_EQ(testData, buffer);
}
TEST(SocketTest, readMoreDataThanIsAvailableFromNonBlockingStream)
{
#ifdef __WINNT__
    GTEST_SKIP() << "Windows does not support non blocking pipes";
#endif
    SocketSetUp     setupSocket;

    int fd[2];
    std::string const testData    = "A line of text\n";
    EXPECT_EQ(0, CREATE_PIPE(fd));
    EXPECT_EQ(testData.size(), ::write(fd[1], testData.c_str(), testData.size()));

    DataSocket      pipeReader(getNormalBuilder(), fd[0]);
    std::string     buffer(testData.size() + 10, '\0');
    ReadInfo read = pipeReader.getMessageData(&buffer[0], testData.size() + 10);
    EXPECT_EQ(true, read.first);
    EXPECT_EQ(testData.size(), read.second);
    buffer.resize(read.second);
    EXPECT_EQ(testData, buffer);

    EXPECT_EQ(0, ::close(fd[1]));
    read = pipeReader.getMessageData(&buffer[0], testData.size() + 10);
    EXPECT_EQ(false, read.first);
    EXPECT_EQ(0, read.second);
}
TEST(SocketTest, writeOneLine)
{
    SocketSetUp     setupSocket;

    int fd[2];
    std::string const testData    = "A line of text\n";
    EXPECT_EQ(0, CREATE_PIPE(fd));

    DataSocket      pipeWriter(getNormalBuilder(), fd[1]);
    pipeWriter.putMessageData(testData.c_str(), testData.size());


    std::string     buffer(testData.size(), '\0');
    EXPECT_EQ(testData.size(), ::read(fd[0], &buffer[0], testData.size()));
    EXPECT_EQ(0, ::close(fd[0]));
    EXPECT_EQ(testData, buffer);
}

