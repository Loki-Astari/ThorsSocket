#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"

using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::SocketBuilder;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::ThorsSocket::Mode;

class TestConnection: public Connection
{
    bool    firstRead;
    bool    firstWrite;
    bool    valid;
    int     id;
    Result  firstReadResult;
    Result  firstWriteResult;
    int*    readCount;
    int*    writeCount;

    public:
        TestConnection(bool valid = true, int id = 12, Result firstReadResult = Result::OK, Result firstWriteResult = Result::OK, int* readCount = nullptr, int* writeCount = nullptr)
            : firstRead(true)
            , firstWrite(true)
            , valid(valid)
            , id(id)
            , firstReadResult(firstReadResult)
            , firstWriteResult(firstWriteResult)
            , readCount(readCount)
            , writeCount(writeCount)
        {}
        virtual bool isConnected()                          const   {return valid;}
        virtual int  socketId(Mode)                         const   {return id;}
        virtual void close()                                        {}
        virtual void tryFlushBuffer()                               {}

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)
        {
            if (readCount) {
                ++(*readCount);
            }
            if (firstRead) {
                firstRead = false;
                return {0, firstReadResult};
            }
            return {size, Result::OK};
        }
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)
        {
            if (writeCount) {
                ++(*writeCount);
            }
            if (firstWrite) {
                firstWrite = false;
                return {0, firstWriteResult};
            }
            return {size, Result::OK};
        }

        virtual std::string errorMessage(ssize_t)                   {return "Testing: 123";}
};

TEST(SocketTest, CreateSocketBuilder)
{
    SocketBuilder               builder;
}

TEST(SocketTest, SocketBuilderUseAllMethods)
{
    SocketBuilder               builder;
    builder.addReadYield([](){});
    builder.addwriteYield([](){});
    builder.addConnection<TestConnection>();
}

TEST(SocketTest, SocketBuilderBuild)
{
    SocketBuilder               builder;
    builder.addReadYield([](){});
    builder.addwriteYield([](){});
    builder.addConnection<TestConnection>();

    Socket                      socket = builder.build();
}

TEST(SocketTest, SocketBuilderTemoraryBuild)
{
    SocketBuilder{}
        .addReadYield([](){})
        .addwriteYield([](){})
        .addConnection<TestConnection>()
        .build();
}

TEST(SocketTest, SocketConstruct)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

    Socket socket   = SocketBuilder{}
                        .addReadYield([&yieldRCount](){++yieldRCount;})
                        .addwriteYield([&yieldWCount](){++yieldWCount;})
                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
                        .addConnection<TestConnection>(true, 11, Result::WouldBlock, Result::WouldBlock)
                        .build();
    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 11);
    ASSERT_EQ(socket.socketId(Mode::Write), 11);

    char block[12];

    socket.getMessageData(block, 12);
    ASSERT_EQ(yieldRCount, 1);

    socket.putMessageData(block, 12);
    ASSERT_EQ(yieldWCount, 1);
}
TEST(SocketTest, SocketConstructFaild)
{
    ASSERT_NO_THROW(
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(false)
                        .build()
    );
}
TEST(SocketTest, SocketConstructMove)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

    Socket socket   = SocketBuilder{}
                        .addReadYield([&yieldRCount](){++yieldRCount;})
                        .addwriteYield([&yieldWCount](){++yieldWCount;})
                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
                        .addConnection<TestConnection>(true, 13, Result::WouldBlock, Result::WouldBlock)
                        .build();

    Socket move = std::move(socket);

    // After moveing `socket is no longer valid`
    // But the `move` should have all the properties of the original.
    ASSERT_FALSE(socket.isConnected());

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 13);
    ASSERT_EQ(move.socketId(Mode::Write), 13);

    char block[12];

    // getMessageData() calls read which returns the WouldBlock which force the readYield functor to be called.
    move.getMessageData(block, 12);
    ASSERT_EQ(yieldRCount, 1);

    // putMessageData() calls write which returns the WouldBlock which force the writeYield functor to be called.
    move.putMessageData(block, 12);
    ASSERT_EQ(yieldWCount, 1);
}
TEST(SocketTest, SocketAssignMove)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

    Socket socket   = SocketBuilder{}
                        .addReadYield([&yieldRCount](){++yieldRCount;})
                        .addwriteYield([&yieldWCount](){++yieldWCount;})
                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
                        .addConnection<TestConnection>(true, 21, Result::WouldBlock, Result::WouldBlock)
                        .build();
    Socket move   = SocketBuilder{}
                        .addConnection<TestConnection>()
                        .build();

    move = std::move(socket);

    ASSERT_FALSE(socket.isConnected());
    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
    ASSERT_EQ(move.socketId(Mode::Write), 21);

    char block[12];

    move.getMessageData(block, 12);
    ASSERT_EQ(yieldRCount, 1);

    move.putMessageData(block, 12);
    ASSERT_EQ(yieldWCount, 1);
}
TEST(SocketTest, SocketSwap)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 21)
                        .build();
    Socket move     = SocketBuilder{}
                        .addConnection<TestConnection>(true, 22)
                        .build();

    move.swap(socket);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketSwapUsingFunction)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 21)
                        .build();
    Socket move     = SocketBuilder{}
                        .addConnection<TestConnection>(true, 22)
                        .build();

    swap(socket, move);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketCheckIdThrowsWhenNotConnected)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13)
                        .build();
    ASSERT_EQ(socket.socketId(Mode::Read), 13);

    Socket move = std::move(socket);

    ASSERT_EQ(move.socketId(Mode::Read), 13);
    ASSERT_THROW(
        socket.socketId(Mode::Read),
        std::runtime_error
    );
}

TEST(SocketTest, SocketReadOK)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13)
                        .build();

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_EQ(result.first, true);
    ASSERT_EQ(result.second, 12);
}
TEST(SocketTest, SocketReadCriticalBug)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::CriticalBug)
                        .build();

    auto action = [&socket]() {
        char buffer[12];
        IOData result = socket.getMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketTest, SocketReadInterupt)
{
    int readCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::Interupt, Result::OK, &readCount)
                        .build();

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 12);
    ASSERT_EQ(readCount, 2);
}
TEST(SocketTest, SocketReadConnectionClosed)
{
    int readCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::ConnectionClosed, Result::OK, &readCount)
                        .build();

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(readCount, 1);
}
TEST(SocketTest, SocketReadUnknown)
{
    int readCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::Unknown, Result::OK, &readCount)
                        .build();

    auto action = [&socket](){
        char buffer[12];
        IOData result = socket.getMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(SocketTest, SocketWriteOK)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13)
                        .build();

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_EQ(result.first, true);
    ASSERT_EQ(result.second, 12);
}
TEST(SocketTest, SocketWriteCriticalBug)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::OK, Result::CriticalBug)
                        .build();

    auto action = [&socket]() {
        char buffer[12];
        IOData result = socket.putMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketTest, SocketWriteInterupt)
{
    int writeCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::OK, Result::Interupt, nullptr, &writeCount)
                        .build();

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 12);
    ASSERT_EQ(writeCount, 2);
}
TEST(SocketTest, SocketWriteConnectionClosed)
{
    int writeCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::OK, Result::ConnectionClosed, nullptr, &writeCount)
                        .build();

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, 0);
    ASSERT_EQ(writeCount, 1);
}
TEST(SocketTest, SocketWriteUnknown)
{
    int writeCount   = 0;
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>(true, 13, Result::OK, Result::Unknown, nullptr, &writeCount)
                        .build();

    auto action = [&socket](){
        char buffer[12];
        IOData result = socket.putMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(SocketTest, CloseNormalSocket)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>()
                        .build();


    socket.close();
}
TEST(SocketTest, CloseNotConnectedSocket)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>()
                        .build();
    Socket move = std::move(socket);

    auto action = [&socket](){
        socket.close();
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
TEST(SocketTest, TryFlushNormal)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>()
                        .build();


    socket.tryFlushBuffer();
}
TEST(SocketTest, TryFlushNotConnectedSocket)
{
    Socket socket   = SocketBuilder{}
                        .addConnection<TestConnection>()
                        .build();
    Socket move = std::move(socket);

    auto action = [&socket](){
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
