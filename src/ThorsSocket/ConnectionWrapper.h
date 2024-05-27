#ifndef THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H
#define THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H

#ifdef __WINNT__
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif

#ifdef  __WINNT__

#define PAUSE_AND_WAIT(n)       Sleep(n * 1000)
#define NONBLOCKING_FLAG        0

int pipe(int fildes[2]);
int thorSetFDNonBlocking(int fd);
int thorSetSocketNonBlocking(SOCKET fd);

class SocketSetUp
{
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
};
#else

#define PAUSE_AND_WAIT(n)       sleep(n)
#define NONBLOCKING_FLAG        O_NONBLOCK


int thorSetFDNonBlocking(int fd);
int thorSetSocketNonBlocking(int fd);
class SocketSetUp {};

#endif

#endif
