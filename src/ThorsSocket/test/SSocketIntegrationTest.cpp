#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"
#include "ConnectionSSocket.h"
#include "test/SimpleServer.h"

#include <utility>
#include <string_view>



using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::ThorsSocket::Mode;

using ThorsAnvil::ThorsSocket::ConnectionType::SSLctxClient;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLctxServer;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocket;
using ThorsAnvil::ThorsSocket::ConnectionType::SSLMethodType;

namespace ConnectionType = ThorsAnvil::ThorsSocket::ConnectionType;

TEST(SSocketIntegrationTest, ConnectToServer)
{
    SSLctxClient      ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "github.com", 443, Blocking::Yes)
                        .build();
    std::string request = "GET / HTTP/1.1\r\n"
                          "Host: github.com\r\n"
                          "User-Agent: ThorSocket/1.0\r\n"
                          "Connection: close\r\n"
                          "Accept: */*\r\n"
                          "\r\n";
    socket.putMessageData(request.c_str(), request.size());
    char buffer[100];
    std::string response;
    for (int loop = 0; loop < 100; ++loop) {
        IOData data = socket.getMessageData(buffer, 100);
        response += std::string_view(buffer, data.second);
        if (!data.first) {
            break;
        }
    }
    auto find = response.find("200 OK");
    ASSERT_NE(find, std::string::npos);
}

TEST(SSocketIntegrationTest, ConnectToServerLocal)
{
    SSLctxServer        ctxServer;
    ServerStart         server;
    server.run<ConnectionType::SSocket>(8080, [](Socket& socket){
        char buffer[10];
        socket.getMessageData(buffer,4);
        socket.putMessageData(buffer,4);
    }, ctxServer);

    SSLctxClient        ctxClient;
    Socket              socket  = SocketBuilder{}
                                    .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                                    .build();
    IOData resultPut = socket.putMessageData("Test", 4);
    char buffer[10];
    IOData resultGet = socket.getMessageData(buffer, 4);
    buffer[resultGet.second] = '\0';
    ASSERT_EQ(std::string("Test"), buffer);
    ASSERT_TRUE(resultPut.first);
    ASSERT_TRUE(resultGet.first);
}


TEST(SSocketIntegrationTest, ConnectToSSocket)
{
    SSLctxServer        ctxServer;
    ServerStart         server;
    server.run<ConnectionType::SSocket>(8080, [](Socket& socket){socket.putMessageData("x", 1);}, ctxServer);

    SSLctxClient        ctxClient;
    Socket              socket  = SocketBuilder{}
                                    .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                                    .build();

    char x;
    socket.getMessageData(&x, 1);

    ASSERT_NE(socket.socketId(Mode::Read), -1);
    ASSERT_NE(socket.socketId(Mode::Write), -1);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLine)
{
    SSLctxServer        ctxServer;
    std::string const message = "This is a line of text\n";
    ServerStart     server;
    server.run<ConnectionType::SSocket>(8080, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size());
    }, ctxServer);


    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                        .build();

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineSlowConnection)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctxServer        ctxServer;
    server.run<ConnectionType::SSocket>(8080, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    }, ctxServer);


    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                        .build();

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineSlowConnectionNonBlockingRead)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctxServer        ctxServer;
    server.run<ConnectionType::SSocket>(8080, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    }, ctxServer);


    int yieldCount = 0;
    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::No)
                        .addReadYield([&yieldCount](){++yieldCount;sleep(2);})
                        .build();

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineCloseEarly)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctxServer        ctxServer;
    server.run<ConnectionType::SSocket>(8080, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size() - 4);
    }, ctxServer);


    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                        .build();

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());
    reply.resize(result.second);

    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketWriteDataUntilYouBlock)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished        = false;
    std::size_t             totalWritten    = 0;

    SSLctxServer        ctxServer;
    server.run<ConnectionType::SSocket>(8080, [&mutex, &cond, &finished, &totalWritten](Socket& socket)
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
    }, ctxServer);

    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::No)
                        .addwriteYield([&mutex, &cond, &finished]()
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            finished = true;
                            cond.notify_all();
                        }
                        )
                        .build();

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

TEST(SSocketIntegrationTest, ConnectToSSocketWriteSmallAmountMakeSureItFlushes)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished = false;

    SSLctxServer        ctxServer;
    server.run<ConnectionType::SSocket>(8080, [&mutex, &cond, &finished, &message](Socket& socket)
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
    }, ctxServer);

    SSLctxClient        ctxClient;
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::SSocket>(ctxClient, "127.0.0.1", 8080, Blocking::Yes)
                        .build();

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
