#include "test/pipe.h"
#include "Socket.h"
#include "ConnectionSSL.h"
#include "Connection.h"
#include "ThorsLogging/ThorsLogging.h"
#include "ThorsIOUtil/Utility.h"
#include "coverage/ThorMock.h"
#include <fstream>
#include <sys/types.h>
#include <gtest/gtest.h>
#include <future>
#include <unistd.h>
#include <fcntl.h>

using ThorsAnvil::ThorsSocket::BaseSocket;
using ThorsAnvil::ThorsSocket::DataSocket;
using ThorsAnvil::ThorsSocket::ConnectSocketNormal;
using ThorsAnvil::ThorsSocket::ServerSocketNormal;
using ThorsAnvil::ThorsSocket::ConnectSocketSSL;
using ThorsAnvil::ThorsSocket::ServerSocketSSL;
using ThorsAnvil::ThorsSocket::ConnectionNormal;
using ThorsAnvil::ThorsSocket::SSLMethod;
using ThorsAnvil::ThorsSocket::SSLctx;;
using ReadInfo = std::pair<bool, std::size_t>;
using ThorsAnvil::ThorsSocket::IOInfo;

static ThorsAnvil::ThorsSocket::ConnectionBuilder getNormalBuilder()
{
    return [](int fd){return std::make_unique<ConnectionNormal>(fd);};
}


class DerivedFromBase: public BaseSocket
{
    public:
        DerivedFromBase()
            : BaseSocket()
        {}
        DerivedFromBase(int socketId, bool blocking = true)
            : BaseSocket(socketId, blocking)
        {}
};

IOInfo badResult(int bad)
{
    return {-1, bad};
}


TEST(SocketExceptionTest, baseSocket_InitFail)
{
    ASSERT_THROW(
        {DerivedFromBase     derived(-1);},
        ThorsAnvil::Logging::CriticalException
    );
}

#if THORS_SOCKET_HEADER_ONLY != 1
TEST(SocketExceptionTest, baseSocketFailNonBlocking)
{
    MOCK_SYS(nonBlockingWrapper, [](int)    {return -1;});
    auto doTest = [](){DerivedFromBase     derived(4, false);};

    ASSERT_THROW(
        {doTest();},
        ThorsAnvil::Logging::CriticalException
    );
}
#endif

TEST(SocketExceptionTest, baseSocketCloseInvalidSocket)
{
    DerivedFromBase     derived1(5);
    DerivedFromBase     derived2(std::move(derived1));

    ASSERT_THROW(
        {derived1.close();},
        ThorsAnvil::Logging::LogicalException
    );
}

#if THORS_SOCKET_HEADER_ONLY != 1
TEST(SocketExceptionTest, CloseFail_EBADF)
{
    MOCK_SYS(closeWrapper, [](int){errno = EBADF;return -1;});

    DerivedFromBase  socket(5);
    ASSERT_THROW(
        socket.close(),
        ThorsAnvil::Logging::CriticalException
    );
}

TEST(SocketExceptionTest, CloseFail_EIO)
{
    MOCK_SYS(closeWrapper, [](int){errno = EIO;return -1;});

    DerivedFromBase  socket(5);
    ASSERT_THROW(
        socket.close(),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, CloseFail_EINTR)
{
    std::cerr << "CloseFail_EINTR: 1\n";
    int count = 0;
    std::cerr << "CloseFail_EINTR: 2\n";
    MOCK_SYS(closeWrapper, [&count](int){
        std::cerr << "Close Wrapper: " << count << "\n";
        ++count;
        if (count == 1) {std::cerr << "BAD\n";errno = EINTR;return -1;}
        std::cerr << "OK\n";
        return 0;
    });
    std::cerr << "CloseFail_EINTR: 3\n";

    DerivedFromBase  socket(5);
    std::cerr << "CloseFail_EINTR: 4\n";
    socket.close();
    std::cerr << "CloseFail_EINTR: 5\n";

    ASSERT_EQ(count, 2);
    std::cerr << "CloseFail_EINTR: 6\n";
    ASSERT_EQ(socket.getSocketId(), -1);
    std::cerr << "CloseFail_EINTR: 7\n";
}
TEST(SocketExceptionTest, CloseFail_Unknown)
{
    MOCK_SYS(closeWrapper, [](int){errno = 9998;return -1;});

    DerivedFromBase  socket(5);
    ASSERT_THROW(
        socket.close(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, ConnectionSocketFailsToOpenSocket)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return -1;});
    auto doTest = [](){ConnectSocketNormal   connect("thorsanvil.com", 80);};

    ASSERT_THROW(
        doTest(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, ConnectionSocketFailsToGetHostByName)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(gethostbyname, [](char const*){return nullptr;});
    auto doTest = [](){ConnectSocketNormal   connect("thorsanvil.com", 80);};

    ASSERT_THROW(
        doTest(),
        std::runtime_error
    );
}
#ifdef __WINNT__
#define THOR_SET_ERROR_NONE         WSASetLastError(0)
#define THOR_SET_ERROR_TRY_AGAIN    WSASetLastError(WSATRY_AGAIN)
#else
#define THOR_SET_ERROR_NONE         h_errno = 0
#define THOR_SET_ERROR_TRY_AGAIN    h_errno = TRY_AGAIN
#endif
TEST(SocketExceptionTest, ConnectionSocketFailsToGetHostByNameTryAgain)
{
    int count = 0;
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(gethostbyname, [&count](char const*){
        ++count;
        THOR_SET_ERROR_NONE;
        if (count == 1) {
            THOR_SET_ERROR_TRY_AGAIN;
        }
        return nullptr;
    });
    auto doTest = [](){ConnectSocketNormal   connect("thorsanvil.com", 80);};

    ASSERT_THROW(
        doTest(),
        std::runtime_error
    );
    ASSERT_EQ(count, 2);
}
TEST(SocketExceptionTest, ConnectionSocketFailsConnect)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(gethostbyname, [](char const*){static char buf[5];static char* bufH[1];static HostEnt result;bufH[0]=buf;result.h_addr_list=bufH;result.h_length=0;return &result;});
    MOCK_SYS(connectWrapper,[](int, SocketAddr const*, std::size_t){return -1;});
    MOCK_SYS(closeWrapper,  [](int){return 0;});
    auto doTest = [](){ConnectSocketNormal   connect("thorsanvil.com", 80);};

    ASSERT_THROW(
        doTest(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, ServerSocketFailsToOpenSocket)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return -1;});
    auto doTest = [](){ServerSocketNormal   server(8080);};

    ASSERT_THROW(
        doTest(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, ServerSocketFailsToBind)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(bindWrapper,   [](int, SocketAddr const*, std::size_t){return -1;});
    MOCK_SYS(closeWrapper,  [](int){return 0;});

    auto doTest = [](){ServerSocketNormal   server(8080, true);};

    ASSERT_THROW(
        doTest(),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, ServerSocketFailsToListen)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(bindWrapper,   [](int, SocketAddr const*, std::size_t){return 0;});
    MOCK_SYS(listnWrapper,  [](int, int){return -1;});
    MOCK_SYS(closeWrapper,  [](int){return 0;});

    auto doTest = [](){ServerSocketNormal   server(8080, true);};

    ASSERT_THROW(
        doTest(),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, ServerSocketAcceptFailsInvalidId)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(bindWrapper,   [](int, SocketAddr const*, std::size_t){return 0;});
    MOCK_SYS(listnWrapper,  [](int, int){return 0;});
    MOCK_SYS(closeWrapper,  [](int){return 0;});

    ServerSocketNormal    server1(8080, true);
    ServerSocketNormal    server2(std::move(server1));
    ASSERT_THROW(
        server1.accept(),
        ThorsAnvil::Logging::LogicalException
    );
}
TEST(SocketExceptionTest, ServerSocketAcceptFailsAcceptCall)
{
    MOCK_SYS(socketWrapper, [](int, int, int){return 5;});
    MOCK_SYS(bindWrapper,   [](int, SocketAddr const*, std::size_t){return 0;});
    MOCK_SYS(listnWrapper,  [](int, int){return 0;});
    MOCK_SYS(closeWrapper,  [](int){return 0;});
    MOCK_SYS(acceptWrapper, [](int, SocketAddr*, socklen_t*){return -1;});

    ServerSocketNormal    server(8080, true);
    ASSERT_THROW(
        server.accept(),
        std::runtime_error
    );
}
#endif

TEST(SocketExceptionTest, DataSocketaReadInvalidId)
{
    DataSocket          data1(getNormalBuilder(), 5, true);
    DataSocket          data2(std::move(data1));

    auto doTest = [](DataSocket& data1){data1.getMessageData(nullptr, 0, 0);};

    ASSERT_THROW(
        doTest(data1),
        ThorsAnvil::Logging::LogicalException
    );
}

#if THORS_SOCKET_HEADER_ONLY != 1
TEST(SocketExceptionTest, DataSocketaReadFailsEBADFOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( EBADF);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsEFAULTOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( EFAULT);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsEINVALOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( EINVAL);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsENXIOOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( ENXIO);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsENOMEMOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( ENOMEM);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsEIOOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( EIO);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsENOBUFSOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( ENOBUFS);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsUnknownOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( 9998);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaReadFailsEINTROnRead)
{
    int count = 0;
    MOCK_SYS(readWrapper,   [&count](int, void*, std::size_t) -> IOInfo {++count; return badResult( count == 1 ? EINTR : EIO); });
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.getMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
    ASSERT_EQ(count, 2);
}
TEST(SocketExceptionTest, DataSocketaReadFailsETIMEDOUTOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( ETIMEDOUT);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.getMessageData(nullptr, 5, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 0);
}
TEST(SocketExceptionTest, DataSocketaReadFailsEAGAINOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( EAGAIN);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.getMessageData(nullptr, 5, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 0);
}
TEST(SocketExceptionTest, DataSocketaReadFailsECONNRESETOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo {return badResult( ECONNRESET);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.getMessageData(nullptr, 5, 0);
    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, 0);
}
TEST(SocketExceptionTest, DataSocketaReadFailsENOTCONNOnRead)
{
    MOCK_SYS(readWrapper,   [](int, void*, std::size_t) -> IOInfo{return badResult( ENOTCONN);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.getMessageData(nullptr, 5, 0);
    ASSERT_FALSE(result.first);
    ASSERT_EQ(result.second, 0);
}
#endif

TEST(SocketExceptionTest, DataSocketaWriteInvalidId)
{
    DataSocket          data1(getNormalBuilder(), 5, true);
    DataSocket          data2(std::move(data1));

    auto doTest = [](DataSocket& data1){data1.putMessageData(nullptr, 0, 0);};

    ASSERT_THROW(
        doTest(data1),
        ThorsAnvil::Logging::LogicalException
    );
}

#if THORS_SOCKET_HEADER_ONLY != 1
TEST(SocketExceptionTest, DataSocketaWriteFailsEINVALOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EINVAL);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEBADFOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EBADF);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsECONNRESETOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ECONNRESET);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsENXIOOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ENXIO);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEPIPEOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EPIPE);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEDQUOTOnRead)
{
#ifdef __WINNT__
    GTEST_SKIP() << "Windows does not support EDQUOT";
#else
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EDQUOT);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
#endif
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEFBIGnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EFBIG);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEIOOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EIO);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsENETDOWNOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ENETDOWN);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsENETUNREACHOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ENETUNREACH);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsENOSPCOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ENOSPC);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsUnknownOnRead)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( 9998);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
}
TEST(SocketExceptionTest, DataSocketaPutMessageCloseFails)
{
    MOCK_SYS(shutdownWrapper,      [](int, int){errno = ENOSPC;return -1;});
    DataSocket          data(getNormalBuilder(), 5, true);

    ASSERT_THROW(
        data.putMessageClose(),
        ThorsAnvil::Logging::CriticalException
    );
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEINTROnWrite)
{
    int count = 0;
    MOCK_SYS(writeWrapper,  [&count](int, void const*, std::size_t){++count; return badResult( count == 1 ? EINTR : EIO);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto doTest = [](DataSocket& data){data.putMessageData(nullptr, 5, 0);};

    ASSERT_THROW(
        doTest(data),
        std::runtime_error
    );
    ASSERT_EQ(count, 2);
}
TEST(SocketExceptionTest, DataSocketaWriteFailsETIMEDOUTOnWrite)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( ETIMEDOUT);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.putMessageData(nullptr, 5, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 0);
}
TEST(SocketExceptionTest, DataSocketaWriteFailsEAGAINOnWrite)
{
    MOCK_SYS(writeWrapper,  [](int, void const*, std::size_t) -> IOInfo {return badResult( EAGAIN);});
    DataSocket          data(getNormalBuilder(), 5, true);

    auto result = data.putMessageData(nullptr, 5, 0);
    ASSERT_TRUE(result.first);
    ASSERT_EQ(result.second, 0);
}
#endif

TEST(SocketExceptionTest, SSLServerConstruct)
{
    SocketSetUp     setupSocket;

    SSLMethod           method(ThorsAnvil::ThorsSocket::SSLMethodType::Server);
    SSLctx              context(method);
    ServerSocketSSL     sslSocket(context, 17834);

    ASSERT_ANY_THROW(
        sslSocket.accept(false);
    );
}
