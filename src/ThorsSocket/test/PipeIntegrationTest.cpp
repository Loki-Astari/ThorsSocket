#include <gtest/gtest.h>
#include "ConnectionPipe.h"
#include "Socket.h"
#include "ThorsLogging/ThorsLogging.h"

#include <thread>

using ThorsAnvil::ThorsSocket::Connection;
using ThorsAnvil::ThorsSocket::Socket;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::Blocking;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::PipeInfo;
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
    Socket              pipe{PipeInfo{Blocking::Yes}};
    PipeServerStart     server([](){});

    ASSERT_NE(pipe.socketId(Mode::Read), -1);
    ASSERT_NE(pipe.socketId(Mode::Write), -1);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLine)
{
    Socket              pipe{PipeInfo{Blocking::Yes}};
    std::string const   message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        pipe.putMessageData(message.c_str(), message.size());
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineSlowConnection)
{
    Socket              pipe{PipeInfo{Blocking::Yes}};
    std::string const   message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            pipe.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineSlowConnectionNonBlockingRead)
{
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    // see ConnectionUtil.cpp
    GTEST_SKIP();
#endif
    int yieldCount = 0;
    Socket              pipe{PipeInfo{Blocking::No},
                                [&yieldCount](){++yieldCount;PAUSE_AND_WAIT(2);}};
    std::string const   message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        std::size_t sent = 0;
        for(std::size_t loop = 0; loop < message.size(); loop += 5) {
            pipe.putMessageData(message.c_str() + loop, std::min(std::size_t{5}, message.size() - sent));
            PAUSE_AND_WAIT(1);
            sent += 5;
        }
    });



    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());

    ASSERT_GE(yieldCount, 0);
    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size());
    ASSERT_EQ(message, reply);
}

TEST(PipeIntegrationTest, ConnectToPipeReadOneLineCloseEarly)
{
    Socket              pipe{PipeInfo{Blocking::Yes}};
    std::string const   message = "This is a line of text\n";
    PipeServerStart     server([&pipe, &message]()
    {
        pipe.putMessageData(message.c_str(), message.size() - 4);
        ::close(pipe.socketId(Mode::Write));
    });


    std::string reply;
    reply.resize(message.size());
    IOData result = pipe.getMessageData(reply.data(), message.size());
    reply.resize(result.dataSize);

    ASSERT_FALSE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(result.dataSize, message.size() - 4);
    ASSERT_EQ(message.substr(0, message.size() - 4), reply);
}

TEST(PipeIntegrationTest, ConnectToPipeWriteDataUntilYouBlock)
{
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    // see ConnectionUtil.cpp
    GTEST_SKIP();
#endif
    std::mutex              mutex;
    std::condition_variable cond;
    bool                    finished        = false;

    Socket  pipe1{PipeInfo{Blocking::No},
                        [](){},
                        [&mutex, &cond, &finished]()
                        {
                            std::unique_lock<std::mutex> lock(mutex);
                            finished = true;
                            cond.notify_all();
                        }
                 };
    Socket  pipe2{PipeInfo{Blocking::Yes}};

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
        totalRead += r.dataSize;
        PAUSE_AND_WAIT(1);

        while (totalRead != totalWritten)
        {
            IOData  r = pipe1.getMessageData(&buffer[0], std::min((totalWritten - totalRead), std::size_t{1000}));
            totalRead += r.dataSize;
            if (!r.stillOpen) {
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
        totalWritten += result.dataSize;
    }

    IOData result = pipe2.getMessageData(&readFromServer, sizeof(readFromServer));
    ASSERT_TRUE(result.stillOpen);
    ASSERT_FALSE(result.blocked);
    ASSERT_EQ(readFromServer, totalWritten);
}

TEST(PipeIntegrationTest, ConnectToPipeWriteSmallAmountMakeSureItFlushes)
{
    Socket  pipe1{PipeInfo{Blocking::Yes}};
    Socket  pipe2{PipeInfo{Blocking::Yes}};

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
        totalRead += r.dataSize;

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
    ASSERT_TRUE(result1.stillOpen);
    ASSERT_FALSE(result1.blocked);
    ASSERT_TRUE(result2.stillOpen);
    ASSERT_FALSE(result2.blocked);
    ASSERT_EQ(readFromServer, result1.dataSize);
}
