#include <gtest/gtest.h>
#include "ConnectionSocket.h"
#include "test/ConnectionSocketTest.h"
#include "test/ConnectionTest.h"

using ThorsAnvil::ThorsSocket::Mode;
using ThorsAnvil::ThorsSocket::ConnectionType::Socket;
using ThorsAnvil::ThorsSocket::ConnectionType::HostEnt;
using ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr;

TEST(ConnectionSocketTest, Construct)
{
    MockConnectionSocket          defaultMockedFunctions;
    int socketCalled = 0;
    int getHCalled = 0;
    int closeCalled = 0;
    int fctlCalled = 0;
    int connectCalled = 0;
    MOCK_SYS(socket,        [&](int, int, int)   {++socketCalled;return 12;});
    auto getHostByNameMock =[&](char const*)     {
        ++getHCalled;
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(close,         [&](int)             {++closeCalled;return 0;});
    MOCK_SYS(connect,       [&](int, SocketAddr const*, unsigned int) {++connectCalled;return 0;});
    MOCK_TSYS(FctlType, fcntl,[&](int, int, int) {++fctlCalled;return 0;});

    {
        Socket                      socket("github.com",80 , Blocking::No);
    }

    ASSERT_EQ(socketCalled,1);
    ASSERT_EQ(getHCalled, 1);
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(fctlCalled, 1);
    ASSERT_EQ(connectCalled, 1);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, SocketCallFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    MOCK_SYS(socket, [](int, int, int)    {return -1;});

    auto action = [](){
        Socket                      socket("github.com", 80, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, GetHostCallFails)
{
    MockConnectionSocket          defaultMockedFunctions;
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
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, GetHostCallFailsTryAgain)
{
    MockConnectionSocket          defaultMockedFunctions;
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
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, ConnectCallFailes)
{
    MockConnectionSocket          defaultMockedFunctions;
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
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, CreateNonBlocking)
{
    MockConnectionSocket          defaultMockedFunctions;
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
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, CreateBlocking)
{
    MockConnectionSocket          defaultMockedFunctions;
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
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, DestructorCallsClose)
{
    MockConnectionSocket          defaultMockedFunctions;
    int callCount = 0;
    MOCK_SYS(close, [&callCount](int)    {++callCount;return 0;});

    {
        Socket                      socket(12);
    }

    ASSERT_EQ(callCount, 1);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, notValidOnMinusOne)
{
    MockConnectionSocket          defaultMockedFunctions;
    Socket                      socket(-1);
    ASSERT_FALSE(socket.isConnected());
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, getSocketIdWorks)
{
    MockConnectionSocket          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        Socket                      socket(12);
        ASSERT_EQ(socket.socketId(Mode::Read), 12);
        ASSERT_EQ(socket.socketId(Mode::Write), 12);
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, Close)
{
    MockConnectionSocket          defaultMockedFunctions;
    int socketCalled = 0;
    int getHCalled = 0;
    int closeCalled = 0;
    int fctlCalled = 0;
    int connectCalled = 0;
    MOCK_SYS(socket,        [&](int, int, int)   {++socketCalled;return 12;});
    auto getHostByNameMock =[&](char const*)     {
        ++getHCalled;
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(close,         [&](int)             {++closeCalled;return 0;});
    MOCK_SYS(connect,       [&](int, SocketAddr const*, unsigned int) {++connectCalled;return 0;});
    MOCK_TSYS(FctlType, fcntl,[&](int, int, int) {++fctlCalled;return 0;});

    Socket                      socket("github.com",80 , Blocking::No);
    socket.close();

    ASSERT_FALSE(socket.isConnected());
    ASSERT_EQ(socketCalled,1);
    ASSERT_EQ(getHCalled, 1);
    ASSERT_EQ(closeCalled, 1);
    ASSERT_EQ(fctlCalled, 1);
    ASSERT_EQ(connectCalled, 1);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, ReadFDSameAsSocketId)
{
    MockConnectionSocket          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        Socket                      socket(33);
        ASSERT_EQ(socket.socketId(Mode::Read), socket.getReadFD());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, WriteFDSameAsSocketId)
{
    MockConnectionSocket          defaultMockedFunctions;
    MOCK_SYS(close,     [](int) {return 0;});

    auto action = [](){
        Socket                      socket(34);
        ASSERT_EQ(socket.socketId(Mode::Write), socket.getWriteFD());
    };
    ASSERT_NO_THROW(
        action()
    );

    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, SetNonBlockingFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    int closeCount = 0;
    MOCK_SYS(socket,    [](int, int, int)   {return 12;});
    MOCK_SYS(close,     [&closeCount](int)  {++closeCount;return 0;});
    auto getHostByNameMock =[](char const*)            {
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(connect,           [] (int, SocketAddr const*, unsigned int) {return 0;});
    MOCK_TSYS(FctlType, fcntl,  [] (int, int, int)                        {return -1;});

    auto action = [](){
        Socket                      socket("google.com", 80, Blocking::No);
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(closeCount, 1);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}

TEST(ConnectionSocketTest, ShutdownFails)
{
    MockConnectionSocket          defaultMockedFunctions;
    int closeCount = 0;
    MOCK_SYS(socket,    [](int, int, int)   {return 12;});
    MOCK_SYS(close,     [&closeCount](int)  {++closeCount;return 0;});
    auto getHostByNameMock =[](char const*)            {
        static char* addrList[] = {""};
        static HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };
    MOCK_SYS(gethostbyname, std::move(getHostByNameMock));
    MOCK_SYS(connect,           [] (int, SocketAddr const*, unsigned int) {return 0;});
    MOCK_TSYS(FctlType, fcntl,  [] (int, int, int)                        {return 0;});
    MOCK_SYS(shutdown,          [] (int, int)                             {return -1;});

    auto action = [](){
        Socket                      socket("google.com", 80, Blocking::No);
        socket.tryFlushBuffer();
    };

    ASSERT_THROW(
        action(),
        std::runtime_error
    );
    ASSERT_EQ(closeCount, 1);
    ASSERT_EQ(defaultMockedFunctions.callCount(), 0);
}
