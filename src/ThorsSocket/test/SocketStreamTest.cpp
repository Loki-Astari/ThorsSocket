#include <gtest/gtest.h>
#include "test/SimpleServer.h"
#include "SocketStream.h"
#include "SocketStreamBuffer.h"

#include <fstream>

using ThorsAnvil::ThorsSocket::SocketStream;
using ThorsAnvil::ThorsSocket::SocketStreamBuffer;
using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::PipeInfo;

TEST(SocketStreamTest, ReadNormal)
{
    SocketStream  stream({"test/data/SocketStreamTest-ReadNormal", Open::Append});

    char data[16];
    std::cout << "Test: Read: " << (void*)data << "\n";
    stream.read(data,16);

    ASSERT_EQ(std::string(data, data + 16), std::string("1234567890ABCDEF"));
}
TEST(SocketStreamTest, ReadNormalInTwoChunks)
{
    SocketStream  stream({"test/data/SocketStreamTest-ReadNormal", Open::Append});

    char data[16];
    stream.read(data, 8);
    //SocketStreamBuffer& buffer = dynamic_cast<SocketStreamBuffer&>(*stream.rdbuf());
    //buffer.resizeInputBuffer(16000);
    stream.read(data + 8, 8);

    ASSERT_EQ(std::string(data, data + 16), std::string("1234567890ABCDEF"));
}
TEST(SocketStreamTest, ReadNormalButHugeChunk)
{
    SocketStream  stream({"test/data/SocketStreamTest-ReadLarge", Open::Append});

    std::vector<char>   data(8000);
    stream.read(&data[0], 8000);
    EXPECT_EQ(8000, stream.gcount());
}
TEST(SocketStreamTest, MoveASocketStream)
{
    SocketSetUp     setupSocket;
    ((void)setupSocket);

    SocketStream  streamOriginal({"test/data/SocketStreamTest-ReadNormal", Open::Append});
    SocketStream  stream(std::move(streamOriginal));

    char data[16];
    stream.read(data,16);

    ASSERT_EQ(std::string(data, data + 16), std::string("1234567890ABCDEF"));
}
TEST(SocketStreamTest, ReadFromSlowStreamToGetEAGAIN)
{
#ifdef  __WINNT__
    GTEST_SKIP() << "Windows does not support nonblocking pipes";
#else
    SocketStream    stream(PipeInfo{});
    Socket&         socket = stream.getSocket();
    int             write = socket.socketId(Mode::Write);

    int testData   = 5;
    int resultData = 0;

    std::thread slowStream([&testData, &write](){
        for(std::size_t loop=0;loop < sizeof(testData); ++loop) {
            usleep(10000);
            ::write(write, reinterpret_cast<char const*>(&testData)+loop, 1);
        }
    });

    stream.read(reinterpret_cast<char*>(&resultData), sizeof(resultData));
    EXPECT_EQ(sizeof(resultData), stream.gcount());

    ASSERT_EQ(testData, resultData);
    slowStream.join();
#endif
}
TEST(SocketStreamTest, ReadPastEOF)
{
    SocketStream  stream({"test/data/SocketStreamTest-ReadNormal", Open::Append});

    char data[16];
    stream.read(data,16);
    EXPECT_EQ(16, stream.gcount());
    stream.read(data,16);
    EXPECT_EQ(1,  stream.gcount());
}

TEST(SocketStreamTest, ReadFail)
{
    SocketStream  stream({"test/data/SocketStreamTest-ReadNormal", Open::Append});
    ::close(stream.getSocket().socketId(Mode::Read));

    char data[16];
    stream.read(data,16);
    EXPECT_EQ(0, stream.gcount());
}
TEST(SocketStreamTest, WriteNormal)
{
    {
        SocketStream  stream({"test/data/SocketStreamTest-WriteNormal", Open::Truncate});

        char data[16] = "12345678";
        stream.write(data, 8);
    }
    {
        std::ifstream   test("test/data/SocketStreamTest-WriteNormal");
        std::string     line;
        std::getline(test, line);
        ASSERT_EQ("12345678", line);
    }
    unlink("test/data/SocketStreamTest-WriteNormal");
}
TEST(SocketStreamTest, WriteNormalMutipleTimes)
{
    {
        SocketStream  stream({"test/data/SocketStreamTest-WriteNormal", Open::Truncate});

        char data[] = "12345678WXYZABCD";
        stream.write(data, 8);
        stream.write(data + 8, 8);
    }
    {
        std::ifstream   test("test/data/SocketStreamTest-WriteNormal");
        std::string     line;
        std::getline(test, line);
        ASSERT_EQ("12345678WXYZABCD", line);
    }
    unlink("test/data/SocketStreamTest-WriteNormal");
}
TEST(SocketStreamTest, WriteNormalWithMove)
{
    {
        SocketStream  streamOriginal({"test/data/SocketStreamTest-WriteNormal", Open::Truncate});
        SocketStream  stream(std::move(streamOriginal));

        char data[16] = "12345678";
        stream.write(data, 8);
    }
    {
        std::ifstream   test("test/data/SocketStreamTest-WriteNormal");
        std::string     line;
        std::getline(test, line);
        ASSERT_EQ("12345678", line);
    }
    unlink("test/data/SocketStreamTest-WriteNormal");
}
TEST(SocketStreamTest, WriteLarge)
{
    SocketStream  stream({"test/data/SocketStreamTest-WriteLarge", Open::Truncate});

    std::vector<char> data(8000);
    stream.write(&data[0], 8000);
    unlink("test/data/SocketStreamTest-WriteLarge");
}
TEST(SocketStreamTest, WriteFail)
{
    SocketStream  stream({"test/data/SocketStreamTest-WriteNormal", Open::Truncate});
    ::close(stream.getSocket().socketId(Mode::Read));

    char data[16] = "12345678";
    stream.write(data,8);
    unlink("test/data/SocketStreamTest-WriteNormal");
}
TEST(SocketStreamTest, WriteToSlowStreamToGetEAGAIN)
{
#ifdef  __WINNT__
    GTEST_SKIP() << "Windows does not support nonblocking pipes";
#else
    SocketStream  stream(PipeInfo{});

    int const blocks   = 4;
    int const actCount = 46;
    int const bufSize  = 524288 / (blocks * actCount);
    std::vector<char> testData(bufSize);
    std::vector<char> resultData(bufSize);

    for(int loop=0; loop < bufSize; ++loop) {
        testData[loop] = ('0' + (loop % 10));
    }

    Socket&     socket = stream.getSocket();
    int         read   = socket.socketId(Mode::Read);

    std::thread slowStream([&resultData, &read]() {
        int rTotal = 0;
        for(int blockLoop = 0; blockLoop < blocks; ++blockLoop)
        {
            sleep(1);
            for(int loop=0;loop < actCount; ++loop)
            {
                int readSoFar = 0;
                while(readSoFar != bufSize)
                {
                    int nextRead = ::read(read, &resultData[readSoFar], bufSize - readSoFar);
                    if (nextRead == 0) {
                        break;
                    }
                    if (nextRead == -1 && errno == EAGAIN)
                    {
                        continue;
                    }
                    ASSERT_NE(-1, nextRead);
                    rTotal += nextRead;
                    readSoFar += nextRead;
                }
            }
        }
        ASSERT_EQ(524216, rTotal);
    });

    std::size_t total = 0;
    std::size_t gCount = 0;
    for(int blockLoop = 0; blockLoop < blocks; ++blockLoop)
    {
        for(int loop=0;loop < actCount; ++loop)
        {
            stream.write(&testData[0], bufSize);
            total += bufSize;
        }
    }
    stream.flush();
    slowStream.join();

    ASSERT_EQ(524216, total);
    ASSERT_EQ(0, gCount);

    for(int loop = 0; loop < bufSize; ++loop) {
        ASSERT_EQ(testData[loop], resultData[loop]);
    }

#endif
}
