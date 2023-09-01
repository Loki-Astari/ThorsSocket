#ifndef THORSANVIL_TEST_CONNECTION_SSOCKET_H
#define THORSANVIL_TEST_CONNECTION_SSOCKET_H

#include "test/ConnectionFileTest.h"

class MockConnectionSSocket: public MockConnectionFile
{
    int count;
    MOCK_MEMBER(TLS_client_method);
    MOCK_MEMBER(TLS_server_method);
    MOCK_MEMBER(SSL_CTX_new);
    MOCK_MEMBER(SSL_CTX_free);
    MOCK_MEMBER(SSL_new);
    MOCK_MEMBER(SSL_free);
    MOCK_MEMBER(SSL_set_fd);
    MOCK_MEMBER(SSL_connect);
    MOCK_MEMBER(SSL_get_error);
    MOCK_MEMBER(SSL_get1_peer_certificate);
    MOCK_MEMBER(SSL_read);
    MOCK_MEMBER(SSL_write);
    MOCK_MEMBER(SSL_shutdown);

    public:
        MockConnectionSSocket()
            : count(0)
            , MOCK_PARAM(TLS_client_method,             [&]()                        {++count;std::cerr << "Unexpected: TLS_client_method\n";return (SSL_METHOD*)1;})
            , MOCK_PARAM(TLS_server_method,             [&]()                        {++count;std::cerr << "Unexpected: TLS_server_method\n";return (SSL_METHOD*)2;})
            , MOCK_PARAM(SSL_CTX_new,                   [&](SSL_METHOD const*)       {++count;std::cerr << "Unexpected: SSL_CTX_new\n";return (SSL_CTX*)2;})
            , MOCK_PARAM(SSL_CTX_free,                  [&](SSL_CTX*)                {++count;std::cerr << "Unexpected: SSL_CTX_free\n";return 1;})
            , MOCK_PARAM(SSL_new,                       [&](SSL_CTX*)                {++count;std::cerr << "Unexpected: SSL_new\n";return (SSL*)3;})
            , MOCK_PARAM(SSL_free,                      [&](SSL*)                    {++count;std::cerr << "Unexpected: SSL_free\n";return 1;})
            , MOCK_PARAM(SSL_set_fd,                    [&](SSL*, int)               {++count;std::cerr << "Unexpected: SSL_set_fd\n";return 1;})
            , MOCK_PARAM(SSL_connect,                   [&](SSL*)                    {++count;std::cerr << "Unexpected: SSL_connect\n";return 1;})
            , MOCK_PARAM(SSL_get_error,                 [&](SSL const*, int)         {++count;std::cerr << "Unexpected: SSL_get_error\n";return 1;})
            , MOCK_PARAM(SSL_get1_peer_certificate,     [&](SSL const*)              {++count;std::cerr << "Unexpected: SSL_get1_peer_certificate\n";return reinterpret_cast<X509*>(0x08);})
            , MOCK_PARAM(SSL_read,                      [&](SSL*, void*, int)        {++count;std::cerr << "Unexpected: SSL_read\n";return 1;})
            , MOCK_PARAM(SSL_write,                     [&](SSL*, void const*, int)  {++count;std::cerr << "Unexpected: SSL_write\n";return 1;})
            , MOCK_PARAM(SSL_shutdown,                  [&](SSL*)                    {++count;std::cerr << "Unexpected: SSL_shutdown\n";return 1;})
        {}
        int callCount() const {return MockConnectionFile::callCount() + count;}
};

#endif
