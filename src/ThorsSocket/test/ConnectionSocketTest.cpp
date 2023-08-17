#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "test/ConnectionTest.h"

using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;

TEST(ConnectionSocketTest, Construct)
{
    Socket                      socket("github.com",80 , Blocking::No);
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    MOCK_SYS(socket, [](int, int, int)    {return -1;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
    int closeCalled = 0;
    int getHCalled = 0;
    MOCK_SYS(socket,        []              (int, int, int)   {return 12;});
    MOCK_SYS(close,         [&closeCalled]  (int)             {++closeCalled;return 0;});
    MOCK_SYS(gethostbyname, [&getHCalled]   (char const*)     {++getHCalled;h_errno = HOST_NOT_FOUND;return nullptr;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    h_errno = NO_DATA;
    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(getHCalled, 1);
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
    int closeCalled = 0;
    int getHCalled = 0;
    MOCK_SYS(socket,        []              (int, int, int)   {return 12;});
    MOCK_SYS(close,         [&closeCalled]  (int)             {++closeCalled;return 0;});
    MOCK_SYS(gethostbyname, [&getHCalled]   (char const*)     {++getHCalled;static int call =0; ++call; h_errno = (call == 1) ? TRY_AGAIN : HOST_NOT_FOUND; return nullptr;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    h_errno = NO_DATA;
    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(getHCalled,  2);
    ASSERT_EQ(h_errno, HOST_NOT_FOUND);
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    int closeCalled = 0;
    int getHCalled = 0;
    int conCalled = 0;
    MOCK_SYS(socket,        []              (int, int, int)         {return 12;});
    MOCK_SYS(close,         [&closeCalled]  (int)                   {++closeCalled;return 0;});
    auto getHostByNameMock =[&getHCalled]  (char const*)            {
        ++getHCalled;
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(connect,       [&conCalled]    (int, SocketAddr const*, unsigned int) {++conCalled;return -1;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    h_errno = NO_DATA;
    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(getHCalled,  1);
    ASSERT_EQ(conCalled,   1);
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    int closeCalled = 0;
    int getHCalled = 0;
    int conCalled = 0;
    int fctlCalled = 0;
    MOCK_SYS(socket,        []              (int, int, int)         {return 12;});
    MOCK_SYS(close,         [&closeCalled]  (int)                   {++closeCalled;return 0;});
    auto getHostByNameMock =[&getHCalled]  (char const*)            {
        ++getHCalled;
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(connect,       [&conCalled]    (int, SocketAddr const*, unsigned int) {++conCalled;return 0;});
    MOCK_TSYS(FctlType, fcntl,[&fctlCalled] (int, int, int)         {++fctlCalled;return 0;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::Yes);
    };

    h_errno = NO_DATA;
    ASSERT_NO_THROW(
        action()
    );
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(getHCalled,  1);
    ASSERT_EQ(conCalled,   1);
    ASSERT_EQ(fctlCalled,  0);
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    int closeCalled = 0;
    int getHCalled = 0;
    int conCalled = 0;
    int fctlCalled = 0;
    MOCK_SYS(socket,        []              (int, int, int)         {return 12;});
    MOCK_SYS(close,         [&closeCalled]  (int)                   {++closeCalled;return 0;});
    auto getHostByNameMock =[&getHCalled]  (char const*)            {
        ++getHCalled;
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(connect,       [&conCalled]    (int, SocketAddr const*, unsigned int) {++conCalled;return 0;});
    MOCK_TSYS(FctlType, fcntl,[&fctlCalled] (int, int, int)         {++fctlCalled;return 0;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    h_errno = NO_DATA;
    ASSERT_NO_THROW(
        action()
    );
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(getHCalled,  1);
    ASSERT_EQ(conCalled,   1);
    ASSERT_EQ(fctlCalled,  1);
}

TEST(ConnectionSocketTest, DestructorCallsClose)
{
    int callCount = 0;
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    {
        Socket                      socket(12);
    }

    ASSERT_EQ(callCount, 1);
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    Socket                      socket(-1);
    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    Socket                      socket(12);
    ASSERT_EQ(socket.socketId(), 12);
}

TEST(ConnectionSocketTest, Close)
{
    Socket                      socket("github.com",80 , Blocking::No);
    socket.close();

    ASSERT_FALSE(socket.isConnected());
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
    Socket                      socket(33);
    ASSERT_EQ(socket.socketId(), socket.getReadFD());
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
    Socket                      socket(34);
    ASSERT_EQ(socket.socketId(), socket.getWriteFD());
}
