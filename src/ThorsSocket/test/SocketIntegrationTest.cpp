#if 0
#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"
#include "ConnectionSocket.h"
#include "test/SimpleServer.h"

#include <thread>

using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Mode;
namespace ConnectionType = ThorsAnvil::ThorsSocket::ConnectionType;

TEST(SocketIntegrationTest, ConnectToSocket)
{
    ServerStart     server;
    server.run<ConnectionType::Socket>(8080, [](Socket&){});

    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)};

    ASSERT_NE(socket.socketId(Mode::Read), -1);
    ASSERT_NE(socket.socketId(Mode::Write), -1);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLine)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;
    server.run<ConnectionType::Socket>(8080, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size());
    });


    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineSlowConnection)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<ConnectionType::Socket>(8080, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    });


    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineSlowConnectionNonBlockingRead)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<ConnectionType::Socket>(8080, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    });


    int yieldCount = 0;
    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::No),
                        [&yieldCount](){++yieldCount;sleep(2);}};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineCloseEarly)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<ConnectionType::Socket>(8080, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size() - 4);
    });


    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());
    reply.resize(result.second);

    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(SocketIntegrationTest, ConnectToSocketWriteDataUntilYouBlock)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished        = false;
    std::size_t             totalWritten    = 0;

    server.run<ConnectionType::Socket>(8080, [&mutex, &cond, &finished, &totalWritten](Socket& socket)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }
        sleep(1);

        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        while (totalRead != totalWritten)
        {
            IOData  r = socket.getMessageData(&buffer[0], std::min((totalWritten - totalRead), std::size_t{1000}));
            totalRead += r.second;
            if (!r.first) {
                break;
            }
        }
        socket.putMessageData(&totalRead, sizeof(totalRead));
    });

    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::No),
                        [](){},
                        [&mutex, &cond, &finished]()
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            finished = true;
                            cond.notify_all();
                        }};

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the socket.
    while (!finished)
    {
        IOData result = socket.putMessageData(message.c_str(), message.size());
        totalWritten += result.second;
    }

    IOData result = socket.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_TRUE(result.first);
    ASSERT_EQ(readFromServer, totalWritten);
}

TEST(SocketIntegrationTest, ConnectToSocketWriteSmallAmountMakeSureItFlushes)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished = false;

    server.run<ConnectionType::Socket>(8080, [&mutex, &cond, &finished, &message](Socket& socket)
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }

        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        IOData  r = socket.getMessageData(&buffer[0], message.size());
        totalRead += r.second;

        socket.putMessageData(&totalRead, sizeof(totalRead));
    });

    Socket  socket{std::make_unique<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)};

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the socket.
    IOData result1 = socket.putMessageData(message.c_str(), message.size());

    {
        std::unique_lock<std::mutex> lock(mutex);
        finished = true;
        cond.notify_all();
    }

    IOData result2 = socket.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_TRUE(result1.first);
    ASSERT_TRUE(result2.first);
    ASSERT_EQ(readFromServer, result1.second);
}
#endif
