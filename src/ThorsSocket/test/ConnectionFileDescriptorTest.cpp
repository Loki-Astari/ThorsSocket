#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"

#include "ConnectionFileDescriptorTest.h"

// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;

TEST(ConnectionFileDescriptorTest, ReadEBADF)
{
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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
    MockConnectionFileDescriptor    defaultMockedFunctions;
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

