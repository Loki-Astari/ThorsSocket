#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;

TEST(TAConnectionFileDescriptorTest, ReadEBADF)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EBADF;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEFAULT)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EFAULT;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEINVAL)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EINVAL;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEISDIR)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EISDIR;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadENOTCONN)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ENOTCONN;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEBADMSG)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EBADMSG;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEOVERFLOW)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EOVERFLOW;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadENXIO)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ENXIO;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadESPIPE)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ESPIPE;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEINTR)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EINTR;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::Interupt);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadECONNRESET)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ECONNRESET;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEAGAIN)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EAGAIN;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadEWOULDBLOCK)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EWOULDBLOCK;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadUnknownError)
{
    /*
     * Using EIO as a proxy for all unknown errors.
     * If we work out how to handle EIO then replace this
     * value with another unhandeled code
     */
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EIO;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, ReadOK)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(read, [](int, void*, ssize_t size) {return size;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::OK);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEBADF)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EBADF;return -1;});
    MOCK_SYS(close, [](int)                         {return 0;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEFAULT)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EFAULT;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEINVAL)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EINVAL;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeENOTCONN)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ENOTCONN;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeENXIO)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ENXIO;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeESPIPE)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ESPIPE;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEDESTADDRREQ)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EDESTADDRREQ;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeERANGE)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ERANGE;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEPIPE)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EPIPE;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEACCES)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EACCES;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::CriticalBug);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEINTR)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EINTR;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::Interupt);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeECONNRESET)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ECONNRESET;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::ConnectionClosed);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEAGAIN)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EAGAIN;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, writeEWOULDBLOCK)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EWOULDBLOCK;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::WouldBlock);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, WriteUnknownError)
{
    /*
     * Using EIO as a proxy for all unknown errors.
     * If we work out how to handle EIO then replace this
     * value with another unhandeled code
     */
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EIO;return -1;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::Unknown);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, WriteOK)
{
    MockDefaultThorsSocket          defaultMockedFunctions;
    MOCK_SYS(write, [](int, const void*, ssize_t size)  {return size;});

    auto action = [](){
        FileDescriptorProxy         file(12);

        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, Result::OK);
    };
    ASSERT_NO_THROW(
        action()
    );
}

TEST(TAConnectionFileDescriptorTest, CheckErrorMsg)
{
    FileDescriptorProxy         file(12);

    errno = EBADF;
    std::string message = file.errorMessage(-1);

    ASSERT_NE(std::string::npos, message.find("EBADF"));
    ASSERT_NE(std::string::npos, message.find("ConnectionType::FileDescriptor"));
}

