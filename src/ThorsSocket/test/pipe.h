#ifndef THORSANVIL_SOCKET_TEST_PIPE_H
#define THORSANVIL_SOCKET_TEST_PIPE_H

#include <stdexcept>

#ifdef  __WINNT__
#include <winsock2.h>
#include <windows.h>
#define     CREATE_PIPE(X)  ::_pipe(X, 256, O_BINARY)
#else
#define     CREATE_PIPE(X)  ::pipe(X)
#endif

class SocketSetUp
{
#ifdef __WINNT__
    public:
        SocketSetUp()
        {
            WSADATA wsaData;
            WORD wVersionRequested = MAKEWORD(2, 2);
            int err = WSAStartup(wVersionRequested, &wsaData);
            if (err != 0) {
                printf("WSAStartup failed with error: %d\n", err);
                throw std::runtime_error("Failed to set up Sockets");
            }
        }
        ~SocketSetUp()
        {

            WSACleanup();
        }
#endif
};

#endif
