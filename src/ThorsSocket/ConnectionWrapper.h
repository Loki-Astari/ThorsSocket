#ifndef THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H
#define THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H


#ifdef  __WINNT__

#define PAUSE_AND_WAIT(n)       Sleep(n * 1000)
#define NONBLOCKING_FLAG        0

int pipe(int fildes[2]);
int ThorSetFDNonBlocking(int fd);
int ThorSetSocketNonBlocking(SOCKET fd);

#else

#define PAUSE_AND_WAIT(n)       sleep(n)
#define NONBLOCKING_FLAG        O_NONBLOCK


int ThorSetFDNonBlocking(int fd);
int ThorSetSocketNonBlocking(int fd);
#endif

#endif
