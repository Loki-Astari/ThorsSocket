#include "ConnectionFileDescriptor.h"
#include "ThorsLogging/ThorsLogging.h"

#include <map>
#include <sstream>

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
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
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
                    " readFromStream",
                    " :SocketCritical exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
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
                    " readFromStream",
                    " :SocketUnknown exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
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
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
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
                    " writeToStream",
                    " :SocketCritical exception thrown.",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
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
                    " readFromStream",
                    " :SocketUnknown exception thrown",
                    " errno = ", errno, " ", getErrNoStrUnix(errno),
                    " msg >", getErrMsgUnix(errno), "<"
                );
        }
    }
    return {static_cast<std::size_t>(chunkWritten), true, false};
}
