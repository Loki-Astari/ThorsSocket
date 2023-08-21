#include <gtest/gtest.h>
#include "Socket.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"
#include "ConnectionPipe.h"

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

class PipeServerStart
{
    std::thread                     serverThread;

    public:
        template<typename F>
        PipeServerStart(F&& action)
            : serverThread(std::move(action))
        {}
        ~PipeServerStart()
        {
            serverThread.join();
        }
};

TEST(PipeIntegrationTest, ConnectToPipe)
{
    Socket  pipe  = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    PipeServerStart     server([&pipe](){});

    ASSERT_NE(pipe.socketId(Mode::Read), -1);
    ASSERT_NE(pipe.socketId(Mode::Write), -1);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLine)
{
    Socket  pipe  = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    std::string const message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        pipe.putMessageData(message.c_str(), message.size());
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineSlowConnection)
{
    Socket  pipe  = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    std::string const message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            pipe.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineSlowConnectionNonBlockingRead)
{
    int yieldCount = 0;
    Socket  pipe  = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::No)
                        .addReadYield([&yieldCount](){++yieldCount;sleep(2);})
                        .build();

    std::string const message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            pipe.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            sleep(1);
            sent += 5;
        }
    });



    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineCloseEarly)
{
    Socket  pipe  = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    std::string const message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        pipe.putMessageData(message.c_str(), message.size() - 4);
        ::close(pipe.socketId(Mode::Write));
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());
    reply.resize(result.second);

    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(PipeIntegrationTest, ConnectToPipeWriteDataUntilYouBlock)
{
    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished        = false;

    Socket  pipe1 = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::No)
                        .addwriteYield([&mutex, &cond, &finished]()
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            finished = true;
                            cond.notify_all();
                        }
                        )
                        .build();
    Socket  pipe2 = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    std::string const message = "This is a line of text\n";

    std::size_t             totalWritten    = 0;

    PipeServerStart     server([&pipe1, &pipe2, &mutex, &cond, &finished, &totalWritten]()
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }
        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        IOData  r = pipe1.getMessageData(&buffer[0], std::min((totalWritten - totalRead), std::size_t{1000}));
        totalRead += r.second;
        sleep(1);

        while (totalRead != totalWritten)
        {
            IOData  r = pipe1.getMessageData(&buffer[0], std::min((totalWritten - totalRead), std::size_t{1000}));
            totalRead += r.second;
            if (!r.first) {
                break;
            }
        }
        pipe2.putMessageData(&totalRead, sizeof(totalRead));
    });

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the pipe.
    while (!finished)
    {
        IOData result = pipe1.putMessageData(message.c_str(), message.size());
        totalWritten += result.second;
    }

    IOData result = pipe2.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_EQ(readFromServer, totalWritten);
}

TEST(PipeIntegrationTest, ConnectToPipeWriteSmallAmountMakeSureItFlushes)
{
    Socket  pipe1 = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();
    Socket  pipe2 = SocketBuilder{}
                        .addConnection<ConnectionType::Pipe>(Blocking::Yes)
                        .build();

    std::string const message = "This is a line of text\n";

    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished = false;

    PipeServerStart     server([&pipe1, &pipe2, &mutex, &cond, &finished, &message]()
    {
        {
            std::unique_lock<std::mutex> lock(mutex);
            cond.wait(lock, [&finished](){return finished;});
        }

        std::vector<char>   buffer(1000);
        std::size_t         totalRead = 0;

        IOData  r = pipe1.getMessageData(&buffer[0], message.size());
        totalRead += r.second;

        pipe2.putMessageData(&totalRead, sizeof(totalRead));
    });

    std::size_t readFromServer = 0;

    // Should write one more message than needed to block the pipe.
    IOData result1 = pipe1.putMessageData(message.c_str(), message.size());

    {
        std::unique_lock<std::mutex> lock(mutex);
        finished = true;
        cond.notify_all();
    }

    IOData result2 = pipe2.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_EQ(readFromServer, result1.second);
}
