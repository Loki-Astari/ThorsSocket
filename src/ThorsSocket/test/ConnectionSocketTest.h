#ifndef THORSANVIL_TEST_CONNECTION_SOCKET_H
#define THORSANVIL_TEST_CONNECTION_SOCKET_H

#include "ConnectionSocket.h"
#include "test/ConnectionFileTest.h"

class MockConnectionSocket: public MockConnectionFile
{
    std::function<ThorsAnvil::ThorsSocket::ConnectionType::HostEnt*(const char*)> getHostByNameMock =[&]  (char const*) {
        static char* addrList[] = {""};
        static ThorsAnvil::ThorsSocket::ConnectionType::HostEnt result {.h_length=1, .h_addr_list=addrList};
        return &result;
    };

    MOCK_MEMBER(socket);
    MOCK_MEMBER(close);
    MOCK_MEMBER(gethostbyname);
    MOCK_MEMBER(connect);
    MOCK_MEMBER(shutdown);

    public:
        MockConnectionSocket()
            : MOCK_PARAM(socket,            [&](int, int, int)       {return 12;})
            , MOCK_PARAM(close,             [&](int)                 {return 0;})
            , MOCK_PARAM(gethostbyname,     std::move(getHostByNameMock))
            , MOCK_PARAM(connect,           [&](int, ThorsAnvil::ThorsSocket::ConnectionType::SocketAddr const*, unsigned int) {return 0;})
            , MOCK_PARAM(shutdown,          [&](int, int)            {return 0;})
        {}
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSocketBlocking()
        {
            return {
                        "Socket",
                        {"socket", "gethostbyname", "connect"},
                        {"close"},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionSocketNonBlocking()
        {
            return {
                        "Socket",
                        {"socket", "gethostbyname", "connect", "fcntl"},
                        {"close"},
                        {}
                   };
        }
};

#endif
