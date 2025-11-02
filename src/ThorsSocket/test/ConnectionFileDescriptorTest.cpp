#include <gtest/gtest.h>
#include "test/ConnectionTest.h"
#include "ConnectionSimpleFile.h"

#include <iostream>

using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::SimpleFile;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;
using ThorsAnvil::ThorsSocket::IOData;


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

TEST(ConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure<std::runtime_error>(EBADF);}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure<std::runtime_error>(EFAULT);}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure<std::runtime_error>(EINVAL);}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure<std::runtime_error>(EISDIR);}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure<std::runtime_error>(EBADMSG);}
TEST(ConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure<std::runtime_error>(ENXIO);}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure<std::runtime_error>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, ReadENOMEM)            {testSocketReadFailure<std::runtime_error>(ENOMEM);}
TEST(ConnectionFileDescriptorTest, ReadENOBUFS)           {testSocketReadFailure<std::runtime_error>(ENOBUFS);}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure<std::runtime_error>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure<std::runtime_error>(EOVERFLOW);}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure<std::runtime_error>(EIO);}
TEST(ConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadReturnError(EWOULDBLOCK, {0, true, true});}


TEST(ConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure<std::runtime_error>(EBADF);}
TEST(ConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure<std::runtime_error>(EFAULT);}
TEST(ConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure<std::runtime_error>(EINVAL);}
TEST(ConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure<std::runtime_error>(ENXIO);}
TEST(ConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure<std::runtime_error>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure<std::runtime_error>(EDESTADDRREQ);}
TEST(ConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure<std::runtime_error>(EPIPE);}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure<std::runtime_error>(EIO);}
TEST(ConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure<std::runtime_error>(EACCES);}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure<std::runtime_error>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure<std::runtime_error>(ERANGE);}
TEST(ConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteReturnError(EWOULDBLOCK, {0, true, true});}

