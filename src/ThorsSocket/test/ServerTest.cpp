#include <gtest/gtest.h>
#include "Server.h"
#include "Socket.h"
#include <thread>

using ThorsAnvil::ThorsSocket::Server;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::ServerInfo;

TEST(ServerTest, ServerCreate)
{
    srand(time(nullptr));
    int port = 8080 + rand() * 200;
    Server  server{ServerInfo{port}, Blocking::Yes, [](){return false;}, [](){return false;}};
}

TEST(ServerTest, serverAcceptConnection)
{
    srand(time(nullptr));
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

