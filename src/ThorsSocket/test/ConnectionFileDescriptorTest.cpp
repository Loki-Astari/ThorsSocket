#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"
#include "ThorsLogging/ThorsLogging.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::Logging::CriticalException;
using ThorsAnvil::Logging::LogicalException;


template<typename Exception>
void testSocketReadFailure(int error)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestThrow<Exception>([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        std::cerr << "Read\n";
        file.readFromStream(buffer, 12);
        std::cerr << "Read DONE\n";
    })
    .expectCallTA(read).toReturn(-1)
    .run();
}
void testSocketReadReturnError(int error, IOData expected)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        IOData result = file.readFromStream(buffer, 12);

        ASSERT_EQ(expected.dataSize,  result.dataSize);
        ASSERT_EQ(expected.stillOpen, result.stillOpen);
        ASSERT_EQ(expected.blocked,   result.blocked);
    })
    .expectCallTA(read).toReturn(-1)
    .run();
}

template<typename Exception>
void testSocketWriteFailure(int error)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestThrow<Exception>([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        file.writeToStream(buffer, 12);
    })
    .expectCallTA(write).toReturn(-1)
    .run();
}

void testSocketWriteReturnError(int error, IOData expected)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        IOData result = file.writeToStream(buffer, 12);

        ASSERT_EQ(expected.dataSize,  result.dataSize);
        ASSERT_EQ(expected.stillOpen, result.stillOpen);
        ASSERT_EQ(expected.blocked,   result.blocked);
    })
    .expectCallTA(write).toReturn(-1)
    .run();
}

TEST(ConnectionFileDescriptorTest, ReadOK)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        IOData result = file.readFromStream(buffer, 12);

        ASSERT_EQ(12,    result.dataSize);
        ASSERT_EQ(true,  result.stillOpen);
        ASSERT_EQ(false, result.blocked);
    })
    .expectCallTA(read).toReturn(12)
    .run();
}

TEST(ConnectionFileDescriptorTest, WriteOK)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestNoThrow([&](){
        char buffer[12];
        IOData result = file.writeToStream(buffer, 12);

        ASSERT_EQ(12,    result.dataSize);
        ASSERT_EQ(true,  result.stillOpen);
        ASSERT_EQ(false, result.blocked);
    })
    .expectCallTA(write).toReturn(12)
    .run();
}

TEST(ConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure<CriticalException>(EBADF);}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure<CriticalException>(EFAULT);}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure<CriticalException>(EINVAL);}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure<CriticalException>(EISDIR);}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure<CriticalException>(EBADMSG);}
TEST(ConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure<CriticalException>(ENXIO);}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure<CriticalException>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, ReadENOMEM)            {testSocketReadFailure<LogicalException>(ENOMEM);}
TEST(ConnectionFileDescriptorTest, ReadENOBUFS)           {testSocketReadFailure<LogicalException>(ENOBUFS);}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure<LogicalException>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure<LogicalException>(EOVERFLOW);}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure<LogicalException>(EIO);}
TEST(ConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadReturnError(EWOULDBLOCK, {0, true, true});}


TEST(ConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure<CriticalException>(EBADF);}
TEST(ConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure<CriticalException>(EFAULT);}
TEST(ConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure<CriticalException>(EINVAL);}
TEST(ConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure<CriticalException>(ENXIO);}
TEST(ConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure<CriticalException>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure<CriticalException>(EDESTADDRREQ);}
TEST(ConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure<CriticalException>(EPIPE);}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure<LogicalException>(EIO);}
TEST(ConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure<LogicalException>(EACCES);}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure<LogicalException>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure<LogicalException>(ERANGE);}
TEST(ConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteReturnError(EWOULDBLOCK, {0, true, true});}

