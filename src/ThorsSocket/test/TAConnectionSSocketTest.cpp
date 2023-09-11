#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"
#include "test/MockDefaultThorsSocket.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::BuildTools::Mock1::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock1::TA_TestNoThrow;


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

TEST(TAConnectionFileDescriptorTest, ReadOK)
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

TEST(TAConnectionFileDescriptorTest, WriteOK)
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


TEST(TAConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure(EBADF, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure(EFAULT, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure(EINVAL, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure(EISDIR, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure(ENOTCONN, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure(EBADMSG, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure(EOVERFLOW, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure(ENXIO, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure(ESPIPE, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadFailure(EINTR, Result::Interupt);}
TEST(TAConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadFailure(ECONNRESET, Result::ConnectionClosed);}
TEST(TAConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadFailure(EAGAIN, Result::WouldBlock);}
TEST(TAConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadFailure(EWOULDBLOCK, Result::WouldBlock);}
TEST(TAConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure(EIO, Result::Unknown);}


TEST(TAConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure(EBADF, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure(EFAULT, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure(EINVAL, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure(ENOTCONN, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure(ENXIO, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure(ESPIPE, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure(EDESTADDRREQ, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure(ERANGE, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure(EPIPE, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure(EACCES, Result::CriticalBug);}
TEST(TAConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteFailure(EINTR, Result::Interupt);}
TEST(TAConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteFailure(ECONNRESET, Result::ConnectionClosed);}
TEST(TAConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteFailure(EAGAIN, Result::WouldBlock);}
TEST(TAConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteFailure(EWOULDBLOCK, Result::WouldBlock);}
TEST(TAConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure(EIO, Result::Unknown);}

TEST(TAConnectionFileDescriptorTest, CheckErrorMsg)
{
    FileDescriptorProxy         file(12);

    errno = EBADF;
    std::string message = file.errorMessage(-1);

    ASSERT_NE(std::string::npos, message.find("EBADF"));
    ASSERT_NE(std::string::npos, message.find("ConnectionType::FileDescriptor"));
}

