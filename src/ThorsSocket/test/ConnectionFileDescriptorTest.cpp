#include <gtest/gtest.h>
#include "ConnectionFile.h"
#include "test/ConnectionTest.h"


// FileDescriptor is virtual (not all virtual methods defined).
//using ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor;
using FileDescriptorProxy = ThorsAnvil::ThorsSocket::ConnectionType::File;
using ThorsAnvil::BuildTools::Mock::TA_TestThrow;
using ThorsAnvil::BuildTools::Mock::TA_TestNoThrow;
using ThorsAnvil::BuildTools::Mock::MockAllDefaultFunctions;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::SocketCritical;
using ThorsAnvil::ThorsSocket::SocketUnknown;

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


TEST(ConnectionFileDescriptorTest, ReadEBADF)             {testSocketReadFailure<SocketCritical>(EBADF);}
TEST(ConnectionFileDescriptorTest, ReadEFAULT)            {testSocketReadFailure<SocketCritical>(EFAULT);}
TEST(ConnectionFileDescriptorTest, ReadEINVAL)            {testSocketReadFailure<SocketCritical>(EINVAL);}
TEST(ConnectionFileDescriptorTest, ReadEISDIR)            {testSocketReadFailure<SocketCritical>(EISDIR);}
TEST(ConnectionFileDescriptorTest, ReadENOTCONN)          {testSocketReadFailure<SocketCritical>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, ReadEBADMSG)           {testSocketReadFailure<SocketCritical>(EBADMSG);}
TEST(ConnectionFileDescriptorTest, ReadEOVERFLOW)         {testSocketReadFailure<SocketCritical>(EOVERFLOW);}
TEST(ConnectionFileDescriptorTest, ReadENXIO)             {testSocketReadFailure<SocketCritical>(ENXIO);}
TEST(ConnectionFileDescriptorTest, ReadESPIPE)            {testSocketReadFailure<SocketCritical>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, ReadUnknownError)      {testSocketReadFailure<SocketUnknown>(EIO);}
TEST(ConnectionFileDescriptorTest, ReadEINTR)             {testSocketReadReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, ReadECONNRESET)        {testSocketReadReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, ReadEAGAIN)            {testSocketReadReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, ReadEWOULDBLOCK)       {testSocketReadReturnError(EWOULDBLOCK, {0, true, true});}


TEST(ConnectionFileDescriptorTest, writeEBADF)            {testSocketWriteFailure<SocketCritical>(EBADF);}
TEST(ConnectionFileDescriptorTest, writeEFAULT)           {testSocketWriteFailure<SocketCritical>(EFAULT);}
TEST(ConnectionFileDescriptorTest, writeEINVAL)           {testSocketWriteFailure<SocketCritical>(EINVAL);}
TEST(ConnectionFileDescriptorTest, writeENOTCONN)         {testSocketWriteFailure<SocketCritical>(ENOTCONN);}
TEST(ConnectionFileDescriptorTest, writeENXIO)            {testSocketWriteFailure<SocketCritical>(ENXIO);}
TEST(ConnectionFileDescriptorTest, writeESPIPE)           {testSocketWriteFailure<SocketCritical>(ESPIPE);}
TEST(ConnectionFileDescriptorTest, writeEDESTADDRREQ)     {testSocketWriteFailure<SocketCritical>(EDESTADDRREQ);}
TEST(ConnectionFileDescriptorTest, writeERANGE)           {testSocketWriteFailure<SocketCritical>(ERANGE);}
TEST(ConnectionFileDescriptorTest, writeEPIPE)            {testSocketWriteFailure<SocketCritical>(EPIPE);}
TEST(ConnectionFileDescriptorTest, writeEACCES)           {testSocketWriteFailure<SocketCritical>(EACCES);}
TEST(ConnectionFileDescriptorTest, WriteUnknownError)     {testSocketWriteFailure<SocketUnknown>(EIO);}
TEST(ConnectionFileDescriptorTest, writeEINTR)            {testSocketWriteReturnError(EINTR, {0, true, false});}
TEST(ConnectionFileDescriptorTest, writeECONNRESET)       {testSocketWriteReturnError(ECONNRESET, {0, false, false});}
TEST(ConnectionFileDescriptorTest, writeEAGAIN)           {testSocketWriteReturnError(EAGAIN, {0, true, true});}
TEST(ConnectionFileDescriptorTest, writeEWOULDBLOCK)      {testSocketWriteReturnError(EWOULDBLOCK, {0, true, true});}

