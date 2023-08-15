#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"

// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;

TEST(ConnectionFileDescriptorTest, ReadEBADF)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EBADF;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EFAULT;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EINVAL;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EISDIR;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ENOTCONN;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EBADMSG;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EOVERFLOW;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadENXIO)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ENXIO;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ESPIPE;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, ReadEINTR)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EINTR;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::Interupt);
}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = ECONNRESET;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::ConnectionClosed);
}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EAGAIN;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::WouldBlock);
}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EWOULDBLOCK;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::WouldBlock);
}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)
{
    /*
     * Using EIO as a proxy for all unknown errors.
     * If we work out how to handle EIO then replace this
     * value with another unhandeled code
     */
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t)      {errno = EIO;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::Unknown);
}
TEST(ConnectionFileDescriptorTest, ReadOK)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(read, [](int, void*, ssize_t size) {return size;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.read(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::OK);
}

TEST(ConnectionFileDescriptorTest, writeEBADF)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EBADF;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEFAULT)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EFAULT;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEINVAL)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EINVAL;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ENOTCONN;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeENXIO)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ENXIO;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeESPIPE)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ESPIPE;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EDESTADDRREQ;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeERANGE)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ERANGE;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEPIPE)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EPIPE;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEACCES)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EACCES;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::CriticalBug);
}
TEST(ConnectionFileDescriptorTest, writeEINTR)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EINTR;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::Interupt);
}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = ECONNRESET;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::ConnectionClosed);
}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EAGAIN;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::WouldBlock);
}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EWOULDBLOCK;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::WouldBlock);
}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)
{
    /*
     * Using EIO as a proxy for all unknown errors.
     * If we work out how to handle EIO then replace this
     * value with another unhandeled code
     */
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t)   {errno = EIO;return -1;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::Unknown);
}
TEST(ConnectionFileDescriptorTest, WriteOK)
{
    MOCK_SYS(close,[](int){return 0;});
    MOCK_SYS(write, [](int, const void*, ssize_t size)  {return size;});
    FileDescriptorProxy         file(12);

    char buffer[12];
    IOResult result = file.write(buffer, 12, 0);

    ASSERT_EQ(result.second, Result::OK);
}


TEST(ConnectionFileDescriptorTest, CheckErrorMsg)
{
    FileDescriptorProxy         file(12);

    errno = EBADF;
    std::string message = file.errorMessage();

    ASSERT_NE(std::string::npos, message.find("EBADF"));
    ASSERT_NE(std::string::npos, message.find("ConnectionType::FileDescriptor"));
}

