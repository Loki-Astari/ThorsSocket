#include "ConnectionUtil.h"

#include <map>
#include <fcntl.h>
#include <string.h>

#ifdef __WINNT__
#include <process.h>

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorCreatePipe(int fildes[2])
{
    return _pipe(fildes, 256, O_BINARY);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorSetFDNonBlocking(int /*fd*/)
{
    // Non Blocking pipe and files are not supported on Windows
    return -1;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorSetSocketNonBlocking(SOCKET fd)
{
    // https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-ioctlsocket
    u_long mode = 1;  // 1 to enable non-blocking socket
    int result = ::ioctlsocket(fd, FIONBIO, &mode);
    return (result == 0) ? 0 : -1;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorCloseSocket(SOCKET fd)
{
    return ::closesocket(fd);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorShutdownSocket(SOCKET fd)
{
    return ::shutdown(fd, SD_SEND);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
char const* getErrNoStrWin(int error)
{
    static std::map<int, char const*> errorString =
    {
        {WSAEPROVIDERFAILEDINIT, "WSAEPROVIDERFAILEDINIT"}, {WSAEINPROGRESS, "WSAEINPROGRESS"}, {WSAEMFILE, "WSAEMFILE"},
        {WSAEINVALIDPROCTABLE, "WSAEINVALIDPROCTABLE"}, {WSAEAFNOSUPPORT, "WSAEAFNOSUPPORT"}, {WSAENOBUFS, "WSAENOBUFS"},
        {WSAEINVALIDPROVIDER, "WSAEINVALIDPROVIDER"}, {WSANOTINITIALISED, "WSANOTINITIALISED"}, {WSAENETDOWN, "WSAENETDOWN"},
        {WSAEPROTONOSUPPORT, "WSAEPROTONOSUPPORT"}, {WSAESOCKTNOSUPPORT, "WSAESOCKTNOSUPPORT"}, {WSAEPROTOTYPE, "WSAEPROTOTYPE"},
        {WSAHOST_NOT_FOUND, "WSAHOST_NOT_FOUND"}, {WSAEMSGSIZE, "WSAEMSGSIZE"}, {WSAEINVAL, "WSAEINVAL"},
        {WSAEADDRNOTAVAIL, "WSAEADDRNOTAVAIL"}, {WSATRY_AGAIN, "WSATRY_AGAIN"}, {WSAEACCES, "WSAEACCES"},
        {WSAECONNREFUSED, "WSAECONNREFUSED"}, {WSAETIMEDOUT, "WSAETIMEDOUT"}, {WSAEFAULT, "WSAEFAULT"},
        {WSAEHOSTUNREACH, "WSAEHOSTUNREACH"}, {WSAESHUTDOWN, "WSAESHUTDOWN"}, {WSANO_DATA, "WSANO_DATA"},
        {WSAECONNABORTED, "WSAECONNABORTED"}, {WSAENETRESET, "WSAENETRESET"}, {WSAEISCONN, "WSAEISCONN"},
        {WSANO_RECOVERY, "WSANO_RECOVERY"}, {WSAEOPNOTSUPP, "WSAEOPNOTSUPP"}, {WSAEALREADY, "WSAEALREADY"},
        {WSAENETUNREACH, "WSAENETUNREACH"}, {WSAEADDRINUSE, "WSAEADDRINUSE"}, {WSAENOTCONN, "WSAENOTCONN"},
        {WSAEWOULDBLOCK, "WSAEWOULDBLOCK"}, {WSAECONNRESET, "WSAECONNRESET"}, {WSAENOTSOCK, "WSAENOTSOCK"},
        {WSAEINTR, "WSAEINTR"},
    };
    auto find = errorString.find(error);
    char const* msg = (find == errorString.end()) ? "Unknown" : find->second;
    return msg;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
char const* getErrMsgWin(int error)
{
    static char msgbuf[1024];
    msgbuf[0] = '\0';
    FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,     // flags
            NULL,                                                           // lpsource
            error,                                                          // message id
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),                      // languageid
            msgbuf,                                                         // output buffer
            sizeof(msgbuf),                                                 // size of msgbuf, bytes
            NULL                                                            // va_list of arguments
            );
    return msgbuf;
}
#else
#include <unistd.h>

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorCreatePipe(int fildes[2])
{
    return pipe(fildes);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorSetFDNonBlocking(int fd)
{
    return ::fcntl(fd, F_SETFL, O_NONBLOCK);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorSetSocketNonBlocking(int fd)
{
    return ::fcntl(fd, F_SETFL, O_NONBLOCK);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorCloseSocket(int fd)
{
    return ::close(fd);
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int thorShutdownSocket(int fd)
{
    return ::shutdown(fd, SHUT_WR);
}

#endif

THORS_SOCKET_HEADER_ONLY_INCLUDE
char const* getErrNoStrUnix(int error)
{
    static std::map<int, char const*> errorString =
    {
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
        {EWOULDBLOCK, "EWOULDBLOCK"},
#endif
        {EOVERFLOW, "EOVERFLOW"},       {EBADF, "EBADF"},       {EFAULT, "EFAULT"},     {EINVAL, "EINVAL"},
        {EBADMSG, "EBADMSG"},           {ENXIO, "ENXIO"},       {ESPIPE, "ESPIPE"},     {EINTR, "EINTR"},
        {ECONNRESET, "ECONNRESET"},     {EAGAIN, "EAGAIN"},     {EISDIR, "EISDIR"},     {EEXIST, "EEXIST"},
        {ENOTCONN, "ENOTCONN"},         {ENOBUFS, "ENOBUFS"},   {EIO, "EIO"},           {ENOMEM, "ENOMEM"},
        {ETIMEDOUT, "ETIMEDOUT"},       {ENOSPC, "ENOSPC"},     {EPERM, "EPERM"},       {EPIPE, "EPIPE"},
        {EDESTADDRREQ, "EDESTADDRREQ"}, {EFBIG, "EFBIG"},       {ERANGE, "ERANGE"},
#ifndef __WINNT__
        {EDQUOT, "EDQUOT"},
#endif
        {ENETUNREACH, "ENETUNREACH"},   {ENETDOWN, "ENETDOWN"}, {EACCES, "EACCES"},     {EBUSY, "EBUSY"},
        {ENAMETOOLONG, "ENAMETOOLONG"}, {ELOOP, "ELOOP"},       {EMFILE, "EMFILE"},     {ENFILE, "ENFILE"},
        {EOPNOTSUPP, "EOPNOTSUPP"},     {ENODEV, "ENODEV"},     {ENOENT, "ENOENT"},     {ENOTDIR, "ENOTDIR"},
        {EAFNOSUPPORT, "EAFNOSUPPORT"}, {EROFS, "EROFS"},       {ETXTBSY, "ETXTBSY"},   {ENOSR, "ENOSR"},
        {EADDRNOTAVAIL, "EADDRNOTAVAIL"},{EALREADY, "EALREADY"},{EISCONN, "EISCONN"},   {ENOTSOCK, "ENOTSOCK"},
        {EPROTONOSUPPORT, "EPROTONOSUPPORT"},                   {EADDRINUSE, "EADDRINUSE"},
        {ECONNREFUSED, "ECONNREFUSED"},                         {EPROTOTYPE, "EPROTOTYPE"},
        {EHOSTUNREACH, "EHOSTUNREACH"},                         {EINPROGRESS, "EINPROGRESS"},
    };
    auto find = errorString.find(error);
    char const* msg = (find == errorString.end()) ? "Unknown" : find->second;
    return msg;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
char const* getErrMsgUnix(int error)
{
    return strerror(error);
}
