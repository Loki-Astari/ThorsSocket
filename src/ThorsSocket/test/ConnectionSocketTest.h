#ifndef THORSANVIL_TEST_CONNECTION_SOCKET_H
#define THORSANVIL_TEST_CONNECTION_SOCKET_H

#include "test/ConnectionFileTest.h"

class MockConnectionSocket: public MockConnectionFile
{
    int count;
    std::function<ThorsAnvil::ThorsSocket::ConnectionType::HostEnt*(const char*)> getHostByNameMock =[&]  (char const*) {
        std::cerr << "Unexpected: gethostbyname\n";
        static char* addrList[] = {""};
        static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=addrList};
        ++count;
        return &result;
    };

    MOCK_MEMBER(socket);
    MOCK_MEMBER(close);
    MOCK_MEMBER(gethostbyname);
    MOCK_MEMBER(connect);
    MOCK_MEMBER(shutdown);

    public:
        MockConnectionSocket()
            : count(0)
            , MOCK_PARAM(socket,            [&](int, int, int)       {++count;std::cerr << "Unexpected: socket\n";return 12;})
            , MOCK_PARAM(close,             [&](int)                 {++count;std::cerr << "Unexpected: close\n";return 0;})
            , MOCK_PARAM(gethostbyname,     std::move(getHostByNameMock))
            , MOCK_PARAM(connect,           [&](int, ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr const*, unsigned int) {++count;std::cerr << "Unexpected: connect\n";return 0;})
            , MOCK_PARAM(shutdown,          [&](int, int)            {++count;std::cerr << "Unexpected: shutdown\n";return 0;})
        {}
        int callCount() const {return MockConnectionFile::callCount() + count;}
};

#endif
