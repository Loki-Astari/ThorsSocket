#include <gtest/gtest.h>
#include "test/SimpleServer.h"
#include "ConnectionSSocket.h"
#include "Socket.h"

#include <iostream>

#define CERT_FILE       "test/data/server/server.crt"
#define KEY_FILE        "test/data/server/server.key"
#define KEY_PASSWD      "TheLongDarkNight"

#define CLIENT_CERT     "test/data/client/client.crt"
#define CLIENT_KEY      "test/data/client/client.key"


using ThorsAnvil::ThorsSocket::ConnectionClient;
using ThorsAnvil::ThorsSocket::SSocketInfo;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::Mode;

using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::DeferAccept;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::CertificateInfo;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::ConnectionType::SSocketClient;

namespace ConnectionType = ThorsAnvil::ThorsSocket::ConnectionType;

TEST(SSocketIntegrationTest, ConnectToServer)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    SocketSetUp         socketSetup;
    ((void)socketSetup);
    SSLctx              ctxClient{SSLMethodType::Client, CertificateInfo{CLIENT_CERT, CLIENT_KEY}};
    Socket              socket{SSocketInfo{"github.com", 443, ctxClient, DeferAccept::No}, Blocking::Yes};
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
        response += std::string_view(buffer, data.dataSize);
        if (!data.stillOpen) {
            break;
        }
    }
    auto find = response.find("200 OK");
    ASSERT_NE(find, std::string::npos);
}

TEST(SSocketIntegrationTest, ConnectToServerLocal)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    SSLctx              ctxServer{SSLMethodType::Server,
                                    CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    ServerStart         server;
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [](Socket& socket){
        char buffer[10];
        socket.getMessageData(buffer,4);
        socket.putMessageData(buffer,4);
    });

    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};
    IOData resultPut = socket.putMessageData("Test", 4);
    char buffer[10];
    IOData resultGet = socket.getMessageData(buffer, 4);
    buffer[resultGet.dataSize] = '\0';
    ASSERT_EQ(std::string("Test"), buffer);
    ASSERT_TRUE(resultPut.stillOpen);
    ASSERT_TRUE(resultGet.stillOpen);
}


TEST(SSocketIntegrationTest, ConnectToSSocket)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    ServerStart         server;
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [](Socket& socket){socket.putMessageData("x", 1);});

    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};

    char x;
    socket.getMessageData(&x, 1);

    ASSERT_NE(socket.socketId(Mode::Read), -1);
    ASSERT_NE(socket.socketId(Mode::Write), -1);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLine)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    std::string const message = "This is a line of text\n";
    ServerStart     server;
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size());
    });


    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineSlowConnection)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });


    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineSlowConnectionNonBlockingRead)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&message](Socket& socket)
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            socket.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });


    int yieldCount = 0;
    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::No};
    socket.setReadYield([&yieldCount](){++yieldCount;PAUSE_AND_WAIT(2);return true;});

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.stillOpen);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketReadOneLineCloseEarly)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size() - 4);
    });


    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};

    std::string reply;
    reply.resize(message.size());
    IOData result = socket.getMessageData(reply.data(), message.size());
    reply.resize(result.dataSize);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_EQ(result.dataSize, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(SSocketIntegrationTest, ConnectToSSocketWriteDataUntilYouBlock)
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

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&mutex, &cond, &finished, &totalWritten](Socket& socket)
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

    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::No};
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
    ASSERT_EQ(readFromServer, totalWritten);
}

TEST(SSocketIntegrationTest, ConnectToSSocketWriteSmallAmountMakeSureItFlushes)
{
#if defined(THOR_DISABLE_TEST_WITH_INTEGRATION)
    GTEST_SKIP();
#endif

    std::string const message = "This is a line of text\n";
    ServerStart     server;

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished = false;

    SSLctx              ctxServer{SSLMethodType::Server,
                                        CertificateInfo{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}}
                                 };
    server.run<SSocketAcceptRequest>(8092, {ctxServer}, [&mutex, &cond, &finished, &message](Socket& socket)
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

    SSLctx              ctxClient{SSLMethodType::Client,
                                        CertificateInfo{CLIENT_CERT, CLIENT_KEY}
                                 };
    Socket              socket{SSocketInfo{"127.0.0.1", 8092, ctxClient, DeferAccept::No}, Blocking::Yes};

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
    ASSERT_TRUE(result2.stillOpen);
    ASSERT_EQ(readFromServer, result1.dataSize);
}
