#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"

using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::Mode;

class TestConnection: public Connection
{
    bool    firstRead;
    bool    firstWrite;
    bool    valid;
    int     id;
    IOData  firstReadResult;
    IOData  firstWriteResult;
    int*    readCount;
    int*    writeCount;

    public:
        TestConnection(bool valid = true, int id = 12, IOData firstReadResult = {0, true, false}, IOData firstWriteResult = {0, true, false}, int* readCount = nullptr, int* writeCount = nullptr)
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
        virtual void release()                                      {}

        virtual IOData readFromStream(char* /*buffer*/, std::size_t size)
        {
            if (readCount) {
                ++(*readCount);
            }
            if (firstRead) {
                firstRead = false;
                if (firstReadResult.dataSize == static_cast<std::size_t>(-1)) {
                    throw std::runtime_error{"Test"};
                }
                if (firstReadResult.dataSize == static_cast<std::size_t>(-2)) {
                    throw std::runtime_error{"Test"};
                }
                return firstReadResult;
            }
            return {size, true, false};
        }
        virtual IOData writeToStream(char const* /*buffer*/, std::size_t size)
        {
            if (writeCount) {
                ++(*writeCount);
            }
            if (firstWrite) {
                firstWrite = false;
                if (firstWriteResult.dataSize == static_cast<std::size_t>(-1)) {
                    throw std::runtime_error{"Test"};
                }
                if (firstWriteResult.dataSize == static_cast<std::size_t>(-2)) {
                    throw std::runtime_error{"Test"};
                }
                return firstWriteResult;
            }
            return {size, true, false};
        }

        virtual std::string errorMessage(ssize_t)                   {return "Testing: 123";}
};

TEST(SocketTest, SocketBuilderBuild)
{
    Socket                      socket{std::make_unique<TestConnection>(), [](){}, [](){}};
}

TEST(SocketTest, SocketConstruct)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
    Socket socket{std::make_unique<TestConnection>(true, 11, IOData{0, true, true}, IOData{0, true, true}),
                        [&yieldRCount](){++yieldRCount;},
                        [&yieldWCount](){++yieldWCount;}};
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
        Socket socket{std::make_unique<TestConnection>(false)};
    );
}
TEST(SocketTest, SocketConstructMove)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, true}, IOData{0, true, true}),
                        [&yieldRCount](){++yieldRCount;},
                        [&yieldWCount](){++yieldWCount;}};

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

                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
    Socket socket{std::make_unique<TestConnection>(true, 21, IOData{0, true, true}, IOData{0, true, true}),
                        [&yieldRCount](){++yieldRCount;},
                        [&yieldWCount](){++yieldWCount;}};
    Socket move{std::make_unique<TestConnection>()};

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
    Socket socket{std::make_unique<TestConnection>(true, 21)};
    Socket move{std::make_unique<TestConnection>(true, 22)};

    move.swap(socket);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketSwapUsingFunction)
{
    Socket socket{std::make_unique<TestConnection>(true, 21)};
    Socket move{std::make_unique<TestConnection>(true, 22)};

    swap(socket, move);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketCheckIdThrowsWhenNotConnected)
{
    Socket socket{std::make_unique<TestConnection>(true, 13)};

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
    Socket socket{std::make_unique<TestConnection>(true, 13)};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_EQ(result.stillOpen, true);
    ASSERT_EQ(result.dataSize, 12);
}
TEST(SocketTest, SocketReadCriticalBug)
{
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{static_cast<std::size_t>(-1), true, false})};

    auto action = [&socket]() {
        char buffer[12];
        socket.getMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
TEST(SocketTest, SocketReadInterupt)
{
    int readCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, false}, IOData{0, true, false}, &readCount)};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 12);
    ASSERT_EQ(readCount, 2);
}
TEST(SocketTest, SocketReadConnectionClosed)
{
    int readCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, false, false}, IOData{0, true, false}, &readCount)};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 0);
    ASSERT_EQ(readCount, 1);
}
TEST(SocketTest, SocketReadUnknown)
{
    int readCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{static_cast<std::size_t>(-2), true, false}, IOData{0, true, false}, &readCount)};

    auto action = [&socket](){
        char buffer[12];
        socket.getMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(SocketTest, SocketWriteOK)
{
    Socket socket{std::make_unique<TestConnection>(true, 13)};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_EQ(result.stillOpen, true);
    ASSERT_EQ(result.dataSize, 12);
}
TEST(SocketTest, SocketWriteCriticalBug)
{
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, false}, IOData{static_cast<std::size_t>(-1), true, false})};

    auto action = [&socket]() {
        char buffer[12];
        socket.putMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
TEST(SocketTest, SocketWriteInterupt)
{
    int writeCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, false}, IOData{0, true, false}, nullptr, &writeCount)};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 12);
    ASSERT_EQ(writeCount, 2);
}
TEST(SocketTest, SocketWriteConnectionClosed)
{
    int writeCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, false}, IOData{0, false, false}, nullptr, &writeCount)};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 0);
    ASSERT_EQ(writeCount, 1);
}
TEST(SocketTest, SocketWriteUnknown)
{
    int writeCount   = 0;
    Socket socket{std::make_unique<TestConnection>(true, 13, IOData{0, true, false}, IOData{static_cast<std::size_t>(-2), true, false}, nullptr, &writeCount)};

    auto action = [&socket](){
        char buffer[12];
        socket.putMessageData(buffer, 12);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(SocketTest, CloseNormalSocket)
{
    Socket socket{std::make_unique<TestConnection>()};

    socket.close();
}
TEST(SocketTest, CloseNotConnectedSocket)
{
    Socket socket{std::make_unique<TestConnection>()};
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
    Socket socket{std::make_unique<TestConnection>()};

    socket.tryFlushBuffer();
}
TEST(SocketTest, TryFlushNotConnectedSocket)
{
    Socket socket{std::make_unique<TestConnection>()};
    Socket move = std::move(socket);

    auto action = [&socket](){
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
