#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;


void testSocketReadFailure(int error, Result expected)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        IOResult result = file.read(buffer, 12, 0);

        ASSERT_EQ(result.second, expected);
    })
    .expectCodeTA(read).toReturn(-1)
    .run();
}

void testSocketWriteFailure(int error, Result expected)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        IOResult result = file.write(buffer, 12, 0);

        ASSERT_EQ(result.second, expected);
    })
    .expectCodeTA(write).toReturn(-1)
    .run();
}

TEST(ConnectionFileDescriptorTest, ReadOK)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        IOResult result = file.read(buffer, 12, 0);
        ASSERT_EQ(result.second, Result::OK);
    })
    .expectCodeTA(read).toReturn(12)
    .run();
}

TEST(ConnectionFileDescriptorTest, WriteOK)
{
    MockDefaultThorsSocket  defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        IOResult result = file.write(buffer, 12, 0);
        ASSERT_EQ(result.second, Result::OK);
    })
    .expectCodeTA(write).toReturn(12)
    .run();
}


TEST(ConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure(EBADF, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure(EFAULT, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure(EINVAL, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure(EISDIR, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure(ENOTCONN, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure(EBADMSG, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure(EOVERFLOW, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure(ENXIO, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure(ESPIPE, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadFailure(EINTR, Result::Interupt);}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadFailure(ECONNRESET, Result::ConnectionClosed);}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadFailure(EAGAIN, Result::WouldBlock);}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadFailure(EWOULDBLOCK, Result::WouldBlock);}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure(EIO, Result::Unknown);}


TEST(ConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure(EBADF, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure(EFAULT, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure(EINVAL, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure(ENOTCONN, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure(ENXIO, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure(ESPIPE, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure(EDESTADDRREQ, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure(ERANGE, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure(EPIPE, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure(EACCES, Result::CriticalBug);}
TEST(ConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteFailure(EINTR, Result::Interupt);}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteFailure(ECONNRESET, Result::ConnectionClosed);}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteFailure(EAGAIN, Result::WouldBlock);}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteFailure(EWOULDBLOCK, Result::WouldBlock);}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure(EIO, Result::Unknown);}

TEST(ConnectionFileDescriptorTest, CheckErrorMsg)
{
    FileDescriptorProxy         file(12);

    errno = EBADF;
    std::string message = file.errorMessage(-1);

    ASSERT_NE(std::string::npos, message.find("EBADF"));
    ASSERT_NE(std::string::npos, message.find("ConnectionType::FileDescriptor"));
}

