#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"
#include "ConnectionSocket.h"

#include <thread>

using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::SocketBuilder;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::IOResult;
using ThorsAnvil::ThorsSocket::Result;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Mode;
namespace ConnectionType = ThorsAnvil::ThorsSocket::ConnectionType;

class Server
{
    int  fd;
    bool bound;
    public:
        Server(int port, Blocking blocking)
            : fd(-1)
            , bound(false)
        {
            fd = ::socket(PF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                throw std::runtime_error("Failed to create socket: ::socket");
            }

            if (blocking == Blocking::No)
            {
                int status = ::fcntl(fd, F_SETFL, O_NONBLOCK);
                if (status == -1) {
                    throw std::runtime_error("Failed to set non-blocking: ::fcntl");
                }
            }
            // During testing
            // we may reuse this socket a lot so allow multiple sockets to bind
            int flag = 1;
            ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(int));

            using SocketAddrIn  = struct ::sockaddr_in;
            using SocketAddrIn  = struct ::sockaddr_in;
            using SocketAddr    = struct ::sockaddr;

            SocketAddrIn    serverAddr = {};
            serverAddr.sin_family       = AF_INET;
            serverAddr.sin_port         = htons(port);
            serverAddr.sin_addr.s_addr  = INADDR_ANY;

            int count = 0;
            do
            {
                if (::bind(fd, reinterpret_cast<SocketAddr*>(&serverAddr), sizeof(serverAddr)) != 0)
                {
                    if (errno == EADDRINUSE && count < 3)
                    {
                        ++count;
                        sleep(10);
                        continue;
                    }
                    close();
                    throw std::runtime_error("Failed to Bind: ::bind");
                }
                // Bind worked.
                // Break out of retry loop.
                break;
            }
            while(true);

            bound = true;
            if (::listen(fd, 5) != 0)
            {
                close();
                throw std::runtime_error("Failed to Listen: ::listen");
            }
        }
        ~Server()
        {
            close();
        }
        void close()
        {
            if (fd != -1) {
                ::close(fd);
            }
            fd = -1;
        }
        Server(Server const&)               = delete;
        Server& operator=(Server const&)    = delete;

        template<typename T, typename... Args>
        Socket accept(Args&&... args)
        {
            int newSocket = ::accept(fd, nullptr, nullptr);
            if (newSocket == -1)
            {
                throw std::runtime_error("Failed t Accept: ::accept");
            }
            return SocketBuilder{}
                    .addConnection<T>(newSocket, std::forward<Args>(args)...)
                    .build();
        }
};

class ServerStart
{
    std::condition_variable         cond;
    std::mutex                      mutex;
    bool                            serverReady;
    std::function<void(Socket&)>    action;
    std::thread                     serverThread;

    template<typename T, typename... Args>
    void server(int port, Args&&... args)
    {
        Server  server(port, Blocking::Yes);
        {
            std::unique_lock<std::mutex> lock(mutex);
            serverReady = true;
            cond.notify_all();
        }

        Socket  socket = server.accept<T>(std::forward<Args>(args)...);
        action(socket);
    };

    public:
        template<typename T, typename F, typename... Args>
        void run(int port, F&& actionP, Args&&... args)
        {
            serverReady     = false;
            action          = std::move(actionP);
            serverThread    = std::thread(&ServerStart::server<T>, this, port, std::forward<Args>(args)...);

            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&serverReady = this->serverReady](){return serverReady;});
        }
        ~ServerStart()
        {
            serverThread.join();
        }
};

TEST(SocketIntegrationTest, ConnectToSocket)
{
    ServerStart     server;
    server.run<ConnectionType::Socket>(8080, [](Socket&){});

    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)
                        .build();

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


    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)
                        .build();

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


    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)
                        .build();

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
    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::No)
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

TEST(SocketIntegrationTest, ConnectToSocketReadOneLineCloseEarly)
{
    std::string const message = "This is a line of text\n";
    ServerStart     server;

    server.run<ConnectionType::Socket>(8080, [&message](Socket& socket)
    {
        socket.putMessageData(message.c_str(), message.size() - 4);
    });


    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)
                        .build();

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

    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::No)
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

    Socket  socket  = SocketBuilder{}
                        .addConnection<ConnectionType::Socket>("127.0.0.1", 8080, Blocking::Yes)
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
    ASSERT_EQ(readFromServer, result1.second);
}

