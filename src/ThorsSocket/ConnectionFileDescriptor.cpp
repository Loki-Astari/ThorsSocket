#include "ConnectionFileDescriptor.h"
#include "ThorsLogging/ThorsLogging.h"

#include <map>
#include <sstream>

#ifdef  __WINNT__
#else
#include <sys/uio.h>
#endif

#include <sys/types.h>
#include <unistd.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;
using ThorsAnvil::ThorsSocket::SocketCritical;
using ThorsAnvil::ThorsSocket::SocketUnknown;

void FileDescriptor::tryFlushBuffer()
{
    // Default Action do nothing.
}

IOData FileDescriptor::readFromStream(char* buffer, std::size_t size)
{
    ssize_t chunkRead = MOCK_FUNC(read)(getReadFD(), buffer, size);
    if (chunkRead == 0) {
        return {0, false, false};
    }
    if (chunkRead == -1)
    {
        // https://man7.org/linux/man-pages/man2/read.2.html
        // https://linux.die.net/man/3/read
        switch (errno)
        {
            case EINTR:         return {0, true, false};
            case ECONNRESET:    return {0, false, false};
#if defined(__WINNT) || (defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1))
            case EWOULDBLOCK:   [[fallthrough]];
#endif
            case EAGAIN:        return {0, true, true};
            case EBADF:         [[fallthrough]];
            case EFAULT:        [[fallthrough]];
            case EINVAL:        [[fallthrough]];
            case EISDIR:        [[fallthrough]];
            case ENOTCONN:      [[fallthrough]];
            case EBADMSG:       [[fallthrough]];
            case EOVERFLOW:     [[fallthrough]];
            case ENXIO:         [[fallthrough]];
            case ESPIPE:
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketCritical,
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    "readFromStream",
                    "SocketCritical ",
                    " errno = ", errno, " ", getErrNoStr(errno),
                    " msg >", strerror(errno), "<"
                );
            case EIO:           [[fallthrough]];
            case ENOBUFS:       [[fallthrough]];
            case ETIMEDOUT:     [[fallthrough]];
            case ENOMEM:        [[fallthrough]];
            default:
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketUnknown,
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    "readFromStream",
                    "SocketUnknown ",
                    " errno = ", errno, " ", getErrNoStr(errno),
                    " msg >", strerror(errno), "<"
                );
        }
    }
    return {static_cast<std::size_t>(chunkRead), true, false};
}

IOData FileDescriptor::writeToStream(char const* buffer, std::size_t size)
{
    ssize_t chunkWritten = MOCK_FUNC(write)(getWriteFD(), buffer, size);
    if (chunkWritten == -1)
    {
        // https://man7.org/linux/man-pages/man2/write.2.html
        // https://linux.die.net/man/3/write
        switch (errno)
        {
            case EINTR:         return {0, true, false};
            case ECONNRESET:    return {0, false, false};
#if defined(__WINNT__) || (defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1))
            case EWOULDBLOCK:   [[fallthrough]];
#endif
            case EAGAIN:        return {0, true, true};
            case EBADF:         [[fallthrough]];
            case EFAULT:        [[fallthrough]];
            case EINVAL:        [[fallthrough]];
            case ENOTCONN:      [[fallthrough]];
            case ENXIO:         [[fallthrough]];
            case ESPIPE:        [[fallthrough]];
            case EDESTADDRREQ:  [[fallthrough]];
            case ERANGE:        [[fallthrough]];
            case EPIPE:         [[fallthrough]];
            case EACCES:
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketCritical,
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    "writeToStream",
                    "SocketCritical ",
                    " errno = ", errno, " ", getErrNoStr(errno),
                    " msg >", strerror(errno), "<"
                );
            case EIO:           [[fallthrough]];
            case ENOBUFS:       [[fallthrough]];
            case ENETUNREACH:   [[fallthrough]];
            case ENETDOWN:      [[fallthrough]];
#ifndef __WINNT__
            case EDQUOT:        [[fallthrough]];
#endif
            case EFBIG:         [[fallthrough]];
            case ENOSPC:        [[fallthrough]];
            case EPERM:         [[fallthrough]];
            default:
                ThorsLogAndThrowAction(
                    ERROR,
                    SocketUnknown,
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    "readFromStream",
                    "SocketUnknown ",
                    " errno = ", errno, " ", getErrNoStr(errno),
                    " msg >", strerror(errno), "<"
                );
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}

char const* FileDescriptor::getErrNoStr(int error)
{
    static const std::map<int, char const*> errorString =
    {
#if defined(__WINNT__) || (defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1))
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
    char const* errorName = find == errorString.end() ? "Unknown" : find->second;
    return errorName;
}
