#include "ConnectionFileDescriptor.h"
#include "ConnectionUtil.h"
#include "ThorsLogging/ThorsLogging.h"

#include <unistd.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOData;

THORS_SOCKET_HEADER_ONLY_INCLUDE
void FileDescriptor::tryFlushBuffer()
{
    // Default Action do nothing.
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
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
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
            case EWOULDBLOCK:   [[fallthrough]];
#endif
            case ETIMEDOUT:     [[fallthrough]];
            case EAGAIN:        return {0, true, true};
            case EBADF:         [[fallthrough]];
            case EFAULT:        [[fallthrough]];
            case EINVAL:        [[fallthrough]];
            case EISDIR:        [[fallthrough]];
            case EBADMSG:       [[fallthrough]];
            case ENXIO:         [[fallthrough]];
            case ESPIPE:
                ThorsLogAndThrowCritical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    " readFromStream",
                    " :SocketCritical exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
                );
            case EOVERFLOW:     [[fallthrough]];
            case ENOTCONN:      [[fallthrough]];
            case EIO:           [[fallthrough]];
            case ENOBUFS:       [[fallthrough]];
            case ENOMEM:        [[fallthrough]];
            default:
                ThorsLogAndThrowLogical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    " readFromStream",
                    " :SocketUnknown exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
                );
        }
    }
    return {static_cast<std::size_t>(chunkRead), true, false};
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
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
            case ENETUNREACH:   [[fallthrough]];
            case ENETDOWN:      [[fallthrough]];
            case ECONNRESET:    return {0, false, false};
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
            case EWOULDBLOCK:   [[fallthrough]];
#endif
            case EAGAIN:        return {0, true, true};
            case EBADF:         [[fallthrough]];
            case EFAULT:        [[fallthrough]];
            case EINVAL:        [[fallthrough]];
            case ENXIO:         [[fallthrough]];
            case ESPIPE:        [[fallthrough]];
            case EDESTADDRREQ:  [[fallthrough]];
            case EPIPE:
                ThorsLogAndThrowCritical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    " writeToStream",
                    " :SocketCritical exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
                );
            case EACCES:        [[fallthrough]];
            case ERANGE:        [[fallthrough]];
            case ENOTCONN:      [[fallthrough]];
            case EIO:           [[fallthrough]];
            case ENOBUFS:       [[fallthrough]];
#ifndef __WINNT__
            case EDQUOT:        [[fallthrough]];
#endif
            case EFBIG:         [[fallthrough]];
            case ENOSPC:        [[fallthrough]];
            case EPERM:         [[fallthrough]];
            default:
                ThorsLogAndThrowLogical(
                    "ThorsAnvil::ThorsSocket::ConnectionType::FileDescriptor",
                    " readFromStream",
                    " :SocketUnknown exception thrown",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
                );
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}
