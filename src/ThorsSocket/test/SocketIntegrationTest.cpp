#include <gtest/gtest.h>
#include "test/SimpleServer.h"
#include "ConnectionSocket.h"
#include "Socket.h"

using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Mode;

TEST(SocketIntegrationTest, ConnectToSocket)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    ServerStart     server;
    server.run<SocketAcceptRequest>(8092, {}, [](Socket&){});

    Socket  socket{{"127.0.0.1", 8092}, Blocking::Yes};

    ASSERT_NE(socket.socketId(Mode::Read), -1);
    ASSERT_NE(socket.socketId(Mode::Write), -1);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLine)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;
    server.run<SocketAcceptRequest>(8092, {}, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size());
    });


    Socket  socket{{"127.0.0.1", 8092}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineSlowConnection)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<SocketAcceptRequest>(8092, {}, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });


    Socket  socket{{"127.0.0.1", 8092}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineSlowConnectionNonBlockingRead)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<SocketAcceptRequest>(8092, {}, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });


    int yieldCount = 0;
    Socket  socket{{"127.0.0.1", 8092}, Blocking::No};
    socket.setReadYield([&yieldCount](){++yieldCount;PAUSE_AND_WAIT(2);return true;});

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineCloseEarly)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<SocketAcceptRequest>(8092, {}, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size() - 4);
    });


    Socket  socket{{"127.0.0.1", 8092}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());
    reply.resize(result.dataSize);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(SocketIntegrationTest, ConnectToSocketWriteDataUntilYouBlock)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished        = false;
    std::size_t             totalWritten    = 0;

    server.run<SocketAcceptRequest>(8092, {}, [&mutex, &cond, &finished, &totalWritten](Socket& socket)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }
        PAUSE_AND_WAIT(1);

        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        while (totalRead != totalWritten)
        {
            IOData  r = socket.getMessageData(&buffer[0], std::min((totalWritten - totalRead), std::size_t{1000}));
            totalRead += r.dataSize;
            if (!r.stillOpen) {
                break;
            }
        }
        socket.putMessageData(&totalRead, sizeof(totalRead));
    });

    Socket  socket{{"127.0.0.1", 8092}, Blocking::No};
    socket.setWriteYield([&mutex, &cond, &finished]()
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            finished = true;
                            cond.notify_all();
                            return true;
                        });

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the socket.
    while (!finished)
    {
        IOData result = socket.putMessageData(message.c_str(), message.size());
        totalWritten += result.dataSize;
    }

    IOData result = socket.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(readFromServer, totalWritten);
}

TEST(SocketIntegrationTest, ConnectToSocketWriteSmallAmountMakeSureItFlushes)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished = false;

    server.run<SocketAcceptRequest>(8092, {}, [&mutex, &cond, &finished, &message](Socket& socket)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }

        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        IOData  r = socket.getMessageData(&buffer[0], message.size());
        totalRead += r.dataSize;

        socket.putMessageData(&totalRead, sizeof(totalRead));
    });

    Socket  socket{{"127.0.0.1", 8092}, Blocking::Yes};

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the socket.
    IOData result1 = socket.putMessageData(message.c_str(), message.size());

    {
        std::unique_lock<std::mutex> lock(mutex);
        finished = true;
        cond.notify_all();
    }

    IOData result2 = socket.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_TRUE(result1.stillOpen);
    ASSERT_FALSE(result1.blocked);
    ASSERT_TRUE(result2.stillOpen);
    ASSERT_FALSE(result2.blocked);
    ASSERT_EQ(readFromServer, result1.dataSize);
}
