#include <gtest/gtest.h>
#include "Server.h"
#include "Socket.h"
#include <thread>

#include <iostream>
struct Mark
{
    Mark() {std::cerr << "Mark\n";}
    ~Mark(){std::cerr << "Mark Done\n";}
};

using ThorsAnvil::ThorsSocket::Server;
using ThorsAnvil::ThorsSocket::Socket;
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



TEST(ServerTest, ServerCreate)
{
    Mark  marker;
    SocketSetUp     setup;

    srand(time(nullptr));
    int port = 8080 + rand() * 200;
    Server  server{ServerInfo{port}, Blocking::Yes, [](){return false;}, [](){return false;}};
}

TEST(ServerTest, serverAcceptConnection)
{
    Mark  marker;
    SocketSetUp     setup;
    int port = 8080 + rand() * 200;

    std::string     message = "TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        Server  server{ServerInfo{port}, Blocking::Yes, [](){return false;}, [](){return false;}};

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

    Socket  socket({"127.0.0.1", port});
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
    Mark  marker;
    SocketSetUp     setup;
    int             port = 8080 + rand() * 200;
    SSLctx          ctx{SSLMethodType::Server};
    Server          server{SServerInfo{port, ctx}, Blocking::Yes, [](){return false;}, [](){return false;}};
}

TEST(ServerTest, SecureserverAcceptConnection)
{
    Mark  marker;
    SocketSetUp     setup;
    int             port = 8080 + rand() * 200;
    CertificateInfo certificate{CERT_FILE, KEY_FILE, [](int){return KEY_PASSWD;}};
    SSLctx          ctx{SSLMethodType::Server, certificate};

    std::string     message = "Secure TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        Server  server{SServerInfo{port, ctx}, Blocking::Yes, [](){return false;}, [](){return false;}};

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
    Socket  socket({"127.0.0.1", port, ctxClient});
    ASSERT_NE(0, socket.socketId(Mode::Read));

    char    buffer[50] = {0};
    socket.getMessageData(buffer, message.size());
    socket.close();
    EXPECT_EQ(message, buffer);

    backgound.join();
}

TEST(ServerTest, SecureserverAcceptConnectionNoPassword)
{
    Mark  marker;
    GTEST_SKIP();
    SocketSetUp     setup;
    int             port = 8080 + rand() * 200;
    CertificateInfo certificate{"/etc/letsencrypt/live/thorsanvil.dev/fullchain.pem",
                                "/etc/letsencrypt/live/thorsanvil.dev/privkey.pem",
                               };
    SSLctx          ctx{SSLMethodType::Server,
                        CertificateInfo{"/etc/letsencrypt/live/thorsanvil.dev/fullchain.pem",
                                        "/etc/letsencrypt/live/thorsanvil.dev/privkey.pem",
                                       }
                       };

    std::string     message = "Secure TestMessage";

    std::mutex              mutex;
    std::condition_variable condition;
    bool                    ready = false;

    std::thread  backgound([&]()
    {
        Server  server{SServerInfo{port, ctx}, Blocking::Yes, [](){return false;}, [](){return false;}};

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
    Socket  socket({"127.0.0.1", port, ctxClient});
    ASSERT_NE(0, socket.socketId(Mode::Read));

    char    buffer[50] = {0};
    socket.getMessageData(buffer, message.size());
    socket.close();
    EXPECT_EQ(message, buffer);

    backgound.join();
}

