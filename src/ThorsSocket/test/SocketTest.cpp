#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "test/SimpleServer.h"

using ThorsAnvil::ThorsSocket::ConnectionClient;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::DeferAccept;
using ThorsAnvil::ThorsSocket::FileInfo;
using ThorsAnvil::ThorsSocket::PipeInfo;
using ThorsAnvil::ThorsSocket::SocketInfo;
using ThorsAnvil::ThorsSocket::SSocketInfo;
using ThorsAnvil::ThorsSocket::SocketInit;


class TestConnection;
struct TestConnectionInfo
{
    using Connection = TestConnection;

    bool    firstRead;
    bool    firstWrite;
    bool    valid;
    int     id;
    IOData  firstReadResult;
    IOData  firstWriteResult;
    int*    readCount;
    int*    writeCount;

    public:
        TestConnectionInfo(bool valid = true, int id = 12, IOData firstReadResult = {0, true, false}, IOData firstWriteResult = {0, true, false}, int* readCount = nullptr, int* writeCount = nullptr)
            : firstRead(true)
            , firstWrite(true)
            , valid(valid)
            , id(id)
            , firstReadResult(firstReadResult)
            , firstWriteResult(firstWriteResult)
            , readCount(readCount)
            , writeCount(writeCount)
        {}
};

class TestConnection: public ConnectionClient
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
        TestConnection(TestConnectionInfo const& info)
            : firstRead(true)
            , firstWrite(true)
            , valid(info.valid)
            , id(info.id)
            , firstReadResult(info.firstReadResult)
            , firstWriteResult(info.firstWriteResult)
            , readCount(info.readCount)
            , writeCount(info.writeCount)
        {}
        virtual bool isConnected()                          const   override {return valid;}
        virtual int  socketId(Mode)                         const   override {return id;}
        virtual void close()                                        override {}
        virtual void tryFlushBuffer()                               override {}
        virtual void release()                                      override {}
        virtual std::string_view protocol() const override {return "test";}

        virtual IOData readFromStream(char* /*buffer*/, std::size_t size)override 
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
        virtual IOData writeToStream(char const* /*buffer*/, std::size_t size)override 
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

TEST(SocketTest, SocketConstructViantFileInfo)
{
    Socket  socket{SocketInit{FileInfo{"test/data/SocketStreamTest-ReadLarge", ThorsAnvil::ThorsSocket::FileMode::Read}}};
}
TEST(SocketTest, SocketConstructFileInfo)
{
    Socket  socket{FileInfo{"test/data/SocketStreamTest-ReadLarge", ThorsAnvil::ThorsSocket::FileMode::Read}};
}
TEST(SocketTest, SocketConstructFileInfoImplied)
{
    Socket  socket{{"test/data/SocketStreamTest-ReadLarge", ThorsAnvil::ThorsSocket::FileMode::Read}};
}

TEST(SocketTest, SocketConstructViantPipeInfo)
{
    Socket  socket{SocketInit{PipeInfo{}}};
}
TEST(SocketTest, SocketConstructPipeInfo)
{
    Socket  socket{PipeInfo{}};
}
TEST(SocketTest, SocketConstructPipeInfoImplied)
{
    // Would be nice to support auto detection of pipes.
    // But the empty constructor matches to many things.
    // Socket  socket{{}};
}
TEST(SocketTest, SocketConstructViantSocketInfo)
{
    SocketSetUp     init;
    Socket  socket{SocketInit{SocketInfo{"google.com", 80}}};
}
TEST(SocketTest, SocketConstructSocketInfo)
{
    SocketSetUp     init;
    Socket  socket{SocketInfo{"google.com", 80}};
}
TEST(SocketTest, SocketConstructSocketInfoImplied)
{
    SocketSetUp     init;
    Socket  socket{{"google.com", 80}};
}
TEST(SocketTest, SocketConstructViantSSocketInfo)
{
    SocketSetUp     init;
    SSLctx  ctx{SSLMethodType::Client};
    Socket  socket{SocketInit{SSocketInfo{"google.com", 443, ctx, DeferAccept::No}}};
}
TEST(SocketTest, SocketConstructSSocketInfo)
{
    SocketSetUp     init;
    SSLctx  ctx{SSLMethodType::Client};
    Socket  socket{SSocketInfo{"google.com", 443, ctx, DeferAccept::No}};
}
TEST(SocketTest, SocketConstructSSocketInfoImplied)
{
    SocketSetUp     init;
    SSLctx  ctx{SSLMethodType::Client};
    Socket  socket{{"google.com", 443, ctx, DeferAccept::No}};
}

TEST(SocketTest, SocketBuilderBuild)
{
    Socket  socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};
}

TEST(SocketTest, SocketConstruct)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 11, IOData{0, true, true}, IOData{0, true, true}}};
    socket.setReadYield([&yieldRCount](){++yieldRCount;return true;});
    socket.setWriteYield([&yieldWCount](){++yieldWCount;return true;});
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
    auto action = [](){Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{false}};};
    ASSERT_NO_THROW(
        action();
    );
}
TEST(SocketTest, SocketConstructMove)
{
    int yieldRCount = 0;
    int yieldWCount = 0;

                        // returning WouldBlock forces Socket to call the yield functions.
                        // This allows us to check if they have been correctly moved.
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, true}, IOData{0, true, true}}};
    socket.setReadYield([&yieldRCount](){++yieldRCount;return true;});
    socket.setWriteYield([&yieldWCount](){++yieldWCount;return true;});

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 21, IOData{0, true, true}, IOData{0, true, true}}};
    socket.setReadYield([&yieldRCount](){++yieldRCount;return true;});
    socket.setWriteYield([&yieldWCount](){++yieldWCount;return true;});
    Socket move{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 21}};
    Socket move{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 22}};

    move.swap(socket);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketSwapUsingFunction)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 21}};
    Socket move{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 22}};

    swap(socket, move);

    ASSERT_TRUE(socket.isConnected());
    ASSERT_EQ(socket.socketId(Mode::Read), 22);

    ASSERT_TRUE(move.isConnected());
    ASSERT_EQ(move.socketId(Mode::Read), 21);
}
TEST(SocketTest, SocketCheckIdThrowsWhenNotConnected)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13}};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_EQ(result.stillOpen, true);
    ASSERT_EQ(result.dataSize, 12);
}
TEST(SocketTest, SocketReadCriticalBug)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{static_cast<std::size_t>(-1), true, false}}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, false}, IOData{0, true, false}, &readCount}};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 12);
    ASSERT_EQ(readCount, 2);
}
TEST(SocketTest, SocketReadConnectionClosed)
{
    int readCount   = 0;
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, false, false}, IOData{0, true, false}, &readCount}};

    char buffer[12];
    IOData result = socket.getMessageData(buffer, 12);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 0);
    ASSERT_EQ(readCount, 1);
}
TEST(SocketTest, SocketReadUnknown)
{
    int readCount   = 0;
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{static_cast<std::size_t>(-2), true, false}, IOData{0, true, false}, &readCount}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13}};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_EQ(result.stillOpen, true);
    ASSERT_EQ(result.dataSize, 12);
}
TEST(SocketTest, SocketWriteCriticalBug)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, false}, IOData{static_cast<std::size_t>(-1), true, false}}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, false}, IOData{0, true, false}, nullptr, &writeCount}};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 12);
    ASSERT_EQ(writeCount, 2);
}
TEST(SocketTest, SocketWriteConnectionClosed)
{
    int writeCount   = 0;
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, false}, IOData{0, false, false}, nullptr, &writeCount}};

    char buffer[12];
    IOData result = socket.putMessageData(buffer, 12);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_EQ(result.dataSize, 0);
    ASSERT_EQ(writeCount, 1);
}
TEST(SocketTest, SocketWriteUnknown)
{
    int writeCount   = 0;
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{true, 13, IOData{0, true, false}, IOData{static_cast<std::size_t>(-2), true, false}, nullptr, &writeCount}};

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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};

    socket.close();
}
TEST(SocketTest, CloseNotConnectedSocket)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};
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
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};

    socket.tryFlushBuffer();
}
TEST(SocketTest, TryFlushNotConnectedSocket)
{
    Socket socket{ThorsAnvil::ThorsSocket::TestMarker::True, TestConnectionInfo{}};
    Socket move = std::move(socket);

    auto action = [&socket](){
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}
