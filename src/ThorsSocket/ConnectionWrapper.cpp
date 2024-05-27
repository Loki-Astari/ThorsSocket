#include "ConnectionWrapper.h"

#ifdef __WINNT__

int pipe(int fildes[2])
{
    return _pipe(fildes, 256, O_BINARY);
}

int ThorSetFDNonBlocking(int fd)
{
    // Non Blocking pipe and files are not supported on Windows
    return -1;
}
int ThorSetSocketNonBlocking(SOCKET fd)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket
    u_long mode = 1;  // 1 to enable non-blocking socket
    int result = ::ioctlsocket(fd, FIONBIO, &mode);
    return (result == 0) ? 0 : -1;
}

#else

int ThorSetFDNonBlocking(int fd)
{
    return ::fcntl(fd, F_SETFL, O_NONBLOCK);
}
int ThorSetSocketNonBlocking(int fd)
{
    return ::fcntl(fd, F_SETFL, O_NONBLOCK);
}

#endif
