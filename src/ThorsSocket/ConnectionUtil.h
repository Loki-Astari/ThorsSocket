#ifndef THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H
#define THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H

#include <stdio.h>
#include <stdexcept>

#ifdef  __WINNT__
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#define PAUSE_AND_WAIT(n)       Sleep(n * 1000)
#define NONBLOCKING_FLAG        0
#define SOCKET_TYPE             SOCKET

int thorCreatePipe(int fd[2]);
int thorSetFDNonBlocking(int fd);
int thorSetSocketNonBlocking(SOCKET fd);
int thorCloseSocket(SOCKET fd);
inline int thorGetSocketError() {return WSAGetLastError();}

#else
#include <sys/socket.h>
#include <netdb.h>
#include <sys/uio.h>
#include <netdb.h>
#include <errno.h>

#define PAUSE_AND_WAIT(n)       sleep(n)
#define NONBLOCKING_FLAG        O_NONBLOCK
#define SOCKET_TYPE             int

int thorCreatePipe(int fd[2]);
int thorSetFDNonBlocking(int fd);
int thorSetSocketNonBlocking(int fd);
int thorCloseSocket(int fd);
inline int thorGetSocketError() {return errno;}

#endif

#endif
