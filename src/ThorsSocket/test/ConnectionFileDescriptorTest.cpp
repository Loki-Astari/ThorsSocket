#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;

TEST(ConnectionFileDescriptorTest, ReadEBADF)
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

TEST(ConnectionFileDescriptorTest, ReadEFAULT)
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

TEST(ConnectionFileDescriptorTest, ReadEINVAL)
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

TEST(ConnectionFileDescriptorTest, ReadEISDIR)
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

TEST(ConnectionFileDescriptorTest, ReadENOTCONN)
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

TEST(ConnectionFileDescriptorTest, ReadEBADMSG)
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

TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)
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

TEST(ConnectionFileDescriptorTest, ReadENXIO)
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

TEST(ConnectionFileDescriptorTest, ReadESPIPE)
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

TEST(ConnectionFileDescriptorTest, ReadEINTR)
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

TEST(ConnectionFileDescriptorTest, ReadECONNRESET)
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

TEST(ConnectionFileDescriptorTest, ReadEAGAIN)
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

TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)
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

TEST(ConnectionFileDescriptorTest, ReadUnknownError)
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

TEST(ConnectionFileDescriptorTest, ReadOK)
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

TEST(ConnectionFileDescriptorTest, writeEBADF)
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

TEST(ConnectionFileDescriptorTest, writeEFAULT)
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

TEST(ConnectionFileDescriptorTest, writeEINVAL)
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

TEST(ConnectionFileDescriptorTest, writeENOTCONN)
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

TEST(ConnectionFileDescriptorTest, writeENXIO)
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

TEST(ConnectionFileDescriptorTest, writeESPIPE)
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

TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)
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

TEST(ConnectionFileDescriptorTest, writeERANGE)
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

TEST(ConnectionFileDescriptorTest, writeEPIPE)
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

TEST(ConnectionFileDescriptorTest, writeEACCES)
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

TEST(ConnectionFileDescriptorTest, writeEINTR)
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

TEST(ConnectionFileDescriptorTest, writeECONNRESET)
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

TEST(ConnectionFileDescriptorTest, writeEAGAIN)
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

TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)
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

TEST(ConnectionFileDescriptorTest, WriteUnknownError)
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

TEST(ConnectionFileDescriptorTest, WriteOK)
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

TEST(ConnectionFileDescriptorTest, CheckErrorMsg)
{
    FileDescriptorProxy         file(12);

    errno = EBADF;
    std::string message = file.errorMessage(-1);

    ASSERT_NE(std::string::npos, message.find("EBADF"));
    ASSERT_NE(std::string::npos, message.find("ConnectionType::FileDescriptor"));
}

