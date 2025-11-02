#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSimpleFile.h"

#include <iostream>

using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::SimpleFile;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::Logging::LogErrorException;
using ThorsAnvil::Logging::LogWarningException;


template<typename Exception>
void testSocketReadFailure(int error)
{
    MockAllDefaultFunctions defaultMockedFunctions;
    FileDescriptorProxy     file(12);

    TA_TestThrow<Exception>([&](){
        char buffer[12];
        errno = error;  // TODO needs to be set in read
        file.readFromStream(buffer, 12);
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
        char buffer[12] = {};
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
        char buffer[12] = {};
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
        char buffer[12] = {};
        IOData result = file.writeToStream(buffer, 12);

        ASSERT_EQ(12,    result.dataSize);
        ASSERT_EQ(true,  result.stillOpen);
        ASSERT_EQ(false, result.blocked);
    })
    .expectCallTA(write).toReturn(12)
    .run();
}

TEST(ConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure<LogErrorException>(EBADF);}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure<LogErrorException>(EFAULT);}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure<LogErrorException>(EINVAL);}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure<LogErrorException>(EISDIR);}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure<LogErrorException>(EBADMSG);}
TEST(ConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure<LogErrorException>(ENXIO);}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure<LogErrorException>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, ReadENOMEM)            {testSocketReadFailure<LogWarningException>(ENOMEM);}
TEST(ConnectionFileDescriptorTest, ReadENOBUFS)           {testSocketReadFailure<LogWarningException>(ENOBUFS);}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure<LogWarningException>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure<LogWarningException>(EOVERFLOW);}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure<LogWarningException>(EIO);}
TEST(ConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadReturnError(EWOULDBLOCK, {0, true, true});}


TEST(ConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure<LogErrorException>(EBADF);}
TEST(ConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure<LogErrorException>(EFAULT);}
TEST(ConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure<LogErrorException>(EINVAL);}
TEST(ConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure<LogErrorException>(ENXIO);}
TEST(ConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure<LogErrorException>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure<LogErrorException>(EDESTADDRREQ);}
TEST(ConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure<LogErrorException>(EPIPE);}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure<LogWarningException>(EIO);}
TEST(ConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure<LogWarningException>(EACCES);}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure<LogWarningException>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure<LogWarningException>(ERANGE);}
TEST(ConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteReturnError(EWOULDBLOCK, {0, true, true});}

