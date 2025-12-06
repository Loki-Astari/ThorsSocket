#include <gtest/gtest.h>
#include "Server.h"
#include "Socket.h"
#include <thread>

#include <iostream>

using ThorsAnvil::ThorsSocket::Server;
using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::DeferAccept;
using ThorsAnvil::ThorsSocket::ServerInit;
using ThorsAnvil::ThorsSocket::SServerInfo;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::SocketInfo;
using ThorsAnvil::ThorsSocket::SSocketInfo;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::ServerInfo;

#define CERT_FILE       "test/data/server/server.crt"
#define KEY_FILE        "test/data/server/server.key"
#define KEY_PASSWD      "TheLongDarkNight"

#define CLIENT_CERT     "test/data/client/client.crt"
#define CLIENT_KEY      "test/data/client/client.key"

class SocketSetUp
{
#ifdef  __WINNT__
    public:
        SocketSetUp()
        {
            WSADATA wsaData;
            WORD wVersionRequested = MAKEWORD(2, 2);
            int err = WSAStartup(wVersionRequested, &wsaData);
            if (err != 0) {
                printf("WSAStartup failed with error: %d\n", err);
                throw std::runtime_error("Failed to set up Sockets");
            }
        }
        ~SocketSetUp()
        {
            WSACleanup();
        }
#endif
};



TEST(ServerTest, ServerCreateVeriantSocket)
{
    SocketSetUp     setup;

    int port = 8000;
    Server  server{ServerInit{ServerInfo{port}}, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSocket)
{
    SocketSetUp     setup;

    int port = 8081;
    Server  server{ServerInfo{port}, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSocketImplied)
{
    SocketSetUp     setup;

    int port = 8082;
    Server  server{port, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSocketWithPort)
{
    SocketSetUp     setup;

    int port = 8083;
    Server  server{port, Blocking::Yes};
}

TEST(ServerTest, ServerCreateVeriantSecureSocket)
{
    SocketSetUp     setup;

    int port = 8084;
    SSLctx  ctx{SSLMethodType::Server};
    Server  server{ServerInit{SServerInfo{port, std::move(ctx)}}, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSecureSocket)
{
    SocketSetUp     setup;

    int port = 8085;
    SSLctx  ctx{SSLMethodType::Server};
    Server  server{SServerInfo{port, std::move(ctx)}, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSecureSocketImplied)
{
    SocketSetUp     setup;

    int port = 8086;
    SSLctx  ctx{SSLMethodType::Server};
    Server  server{{port, std::move(ctx)}, Blocking::Yes};
}

TEST(ServerTest, ServerCreateSecureSocketPortCTX)
{
    SocketSetUp     setup;

    int port = 8087;
    SSLctx  ctx{SSLMethodType::Server};
    Server  server{port, std::move(ctx), Blocking::Yes};
}

TEST(ServerTest, serverAcceptConnection)
{
    SocketSetUp     setup;
    int port = 8088;

    std::string     message = "TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        Server  server{ServerInfo{port}, Blocking::Yes};

        {
            std::unique_lock        lock(mutex);
            ready = true;
            condition.notify_one();
        }

        Socket  client = server.accept(Blocking::Yes);

        ASSERT_NE(0, client.socketId(Mode::Read));

        client.putMessageData(message.c_str(), message.size());
    });


    std::unique_lock        lock(mutex);
    condition.wait(lock, [&]{return ready;});

    Socket  socket(SocketInfo{"127.0.0.1", port});
    ASSERT_NE(0, socket.socketId(Mode::Read));

    char    buffer[12] = {0};
    socket.getMessageData(buffer, message.size());
    EXPECT_EQ(message, buffer);

    backgound.join();
}

using ThorsAnvil::ThorsSocket::SSLctx;
using ThorsAnvil::ThorsSocket::CertificateInfo;
using ThorsAnvil::ThorsSocket::SSLMethodType;
using ThorsAnvil::ThorsSocket::SServerInfo;


TEST(ServerTest, SecureServerCreate)
{
    SocketSetUp     setup;
    int             port = 8089;
    SSLctx          ctx{SSLMethodType::Server};
    Server          server{SServerInfo{port, std::move(ctx)}};
}

TEST(ServerTest, SecureserverAcceptConnection)
{
    SocketSetUp     setup;
    int             port = 8090;
    CertificateInfo certificate{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}};

    std::string     message = "Secure TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        SSLctx          ctx{SSLMethodType::Server, certificate};
        Server  server{SServerInfo{port, std::move(ctx)}};

        {
            std::unique_lock        lock(mutex);
            ready = true;
            condition.notify_one();
        }

        Socket  client = server.accept(Blocking::Yes);

        ASSERT_NE(0, client.socketId(Mode::Read));

        client.putMessageData(message.c_str(), message.size());
    });


    std::unique_lock        lock(mutex);
    condition.wait(lock, [&]{return ready;});

    CertificateInfo certificateClient{CLIENT_CERT, CLIENT_KEY};
    SSLctx          ctxClient{SSLMethodType::Client, certificateClient};
    Socket  socket(SSocketInfo{"127.0.0.1", port, ctxClient, DeferAccept::No});
    ASSERT_NE(0, socket.socketId(Mode::Read));

    char    buffer[50] = {0};
    socket.getMessageData(buffer, message.size());
    socket.close();
    EXPECT_EQ(message, buffer);

    backgound.join();
}

TEST(ServerTest, SecureserverAcceptConnectionNoPassword)
{
    GTEST_SKIP();
    SocketSetUp     setup;
    int             port = 8091;
    CertificateInfo certificate{"/etc/letsencrypt/live/thorsanvil.dev/fullchain.pem",
                                "/etc/letsencrypt/live/thorsanvil.dev/privkey.pem",
                               };

    std::string     message = "Secure TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        SSLctx          ctx{SSLMethodType::Server,
                            CertificateInfo{"/etc/letsencrypt/live/thorsanvil.dev/fullchain.pem",
                                            "/etc/letsencrypt/live/thorsanvil.dev/privkey.pem",
                                           }
                           };
        Server  server{SServerInfo{port, std::move(ctx)}, Blocking::Yes};

        {
            std::unique_lock        lock(mutex);
            ready = true;
            condition.notify_one();
        }

        Socket  client = server.accept(Blocking::Yes);

        ASSERT_NE(0, client.socketId(Mode::Read));

        client.putMessageData(message.c_str(), message.size());
    });


    std::unique_lock        lock(mutex);
    condition.wait(lock, [&]{return ready;});

    CertificateInfo certificateClient{CLIENT_CERT, CLIENT_KEY};
    SSLctx          ctxClient{SSLMethodType::Client, certificateClient};
    Socket  socket(SSocketInfo{"127.0.0.1", port, ctxClient, DeferAccept::No});
    ASSERT_NE(0, socket.socketId(Mode::Read));

    char    buffer[50] = {0};
    socket.getMessageData(buffer, message.size());
    socket.close();
    EXPECT_EQ(message, buffer);

    backgound.join();
}

