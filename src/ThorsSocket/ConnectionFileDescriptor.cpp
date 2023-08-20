#include "ConnectionFileDescriptor.h"

#include <map>
#include <sstream>

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;
using ThorsAnvil::ThorsSocket::IOResult;

void FileDescriptor::tryFlushBuffer()
{
    // Default Action do nothing.
}

IOResult FileDescriptor::read(char* buffer, std::size_t size, std::size_t dataRead)
{
    while (dataRead != size)
    {
        ssize_t chunkRead = MOCK_FUNC(read)(getReadFD(), buffer + dataRead, size - dataRead);
        if (chunkRead == 0) {
            return {dataRead, Result::ConnectionClosed};
        }
        if (chunkRead == -1)
        {
            // https://man7.org/linux/man-pages/man2/read.2.html
            // https://linux.die.net/man/3/read
            switch (errno)
            {
                case EBADF:
                case EFAULT:
                case EINVAL:
                case EISDIR:
                case ENOTCONN:
                case EBADMSG:
                case EOVERFLOW:
                case ENXIO:
                case ESPIPE:
                    return {dataRead, Result::CriticalBug};
                case EINTR:
                    return {dataRead, Result::Interupt};
                case ECONNRESET:
                    return {dataRead, Result::ConnectionClosed};
                case EAGAIN:
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
                case EWOULDBLOCK:
#endif
                    return {dataRead, Result::WouldBlock};
                case EIO:
                case ENOBUFS:
                case ETIMEDOUT:
                case ENOMEM:
                default:
                    return {dataRead, Result::Unknown};
            }
        }
        dataRead += chunkRead;
    }
    return {dataRead, Result::OK};
}

IOResult FileDescriptor::write(char const* buffer, std::size_t size, std::size_t dataWritten)
{
    while (dataWritten != size)
    {
        ssize_t chunkWritten = MOCK_FUNC(write)(getWriteFD(), buffer + dataWritten, size - dataWritten);
        if (chunkWritten == -1)
        {
            // https://man7.org/linux/man-pages/man2/write.2.html
            // https://linux.die.net/man/3/write
            switch (errno)
            {
                case EBADF:
                case EFAULT:
                case EINVAL:
                case ENOTCONN:
                case ENXIO:
                case ESPIPE:
                case EDESTADDRREQ:
                case ERANGE:
                case EPIPE:
                case EACCES:
                    return {dataWritten, Result::CriticalBug};
                case EINTR:
                    return {dataWritten, Result::Interupt};
                case ECONNRESET:
                    return {dataWritten, Result::ConnectionClosed};
                case EAGAIN:
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
                case EWOULDBLOCK:
#endif
                    return {dataWritten, Result::WouldBlock};
                case EIO:
                case ENOBUFS:
                case ENETUNREACH:
                case ENETDOWN:
                case EDQUOT:
                case EFBIG:
                case ENOSPC:
                case EPERM:
                default:
                    return {dataWritten, Result::Unknown};
            }
        }
        dataWritten += chunkWritten;
    }
    return {dataWritten, Result::OK};
}

std::string FileDescriptor::errorMessage()
{
    return buildErrorMessage();
}

std::string FileDescriptor::buildErrorMessage()
{
    static const std::map<int, char const*> errorString =
    {
#if defined(HAS_UNIQUE_EWOULDBLOCK) && (HAS_UNIQUE_EWOULDBLOCK == 1)
        {EWOULDBLOCK, "EWOULDBLOCK"},
#endif
        {EOVERFLOW, "EOVERFLOW"},       {EBADF, "EBADF"},       {EFAULT, "EFAULT"},     {EINVAL, "EINVAL"},
        {EBADMSG, "EBADMSG"},           {ENXIO, "ENXIO"},       {ESPIPE, "ESPIPE"},     {EINTR, "EINTR"},
        {ECONNRESET, "ECONNRESET"},     {EAGAIN, "EAGAIN"},     {EISDIR, "EISDIR"},     {EEXIST, "EEXIST"},
        {ENOTCONN, "ENOTCONN"},         {ENOBUFS, "ENOBUFS"},   {EIO, "EIO"},           {ENOMEM, "ENOMEM"},
        {ETIMEDOUT, "ETIMEDOUT"},       {ENOSPC, "ENOSPC"},     {EPERM, "EPERM"},       {EPIPE, "EPIPE"},
        {EDESTADDRREQ, "EDESTADDRREQ"}, {EDQUOT, "EDQUOT"},     {EFBIG, "EFBIG"},       {ERANGE, "ERANGE"},
        {ENETUNREACH, "ENETUNREACH"},   {ENETDOWN, "ENETDOWN"}, {EACCES, "EACCES"},     {EBUSY, "EBUSY"},
        {ENAMETOOLONG, "ENAMETOOLONG"}, {ELOOP, "ELOOP"},       {EMFILE, "EMFILE"},     {ENFILE, "ENFILE"},
        {EOPNOTSUPP, "EOPNOTSUPP"},     {ENODEV, "ENODEV"},     {ENOENT, "ENOENT"},     {ENOTDIR, "ENOTDIR"},
        {EAFNOSUPPORT, "EAFNOSUPPORT"}, {EROFS, "EROFS"},       {ETXTBSY, "ETXTBSY"},   {ENOSR, "ENOSR"},
        {EADDRNOTAVAIL, "EADDRNOTAVAIL"},{EALREADY, "EALREADY"},{EISCONN, "EISCONN"},   {ENOTSOCK, "ENOTSOCK"},
        {EPROTONOSUPPORT, "EPROTONOSUPPORT"},                   {EADDRINUSE, "EADDRINUSE"},
        {ECONNREFUSED, "ECONNREFUSED"},                         {EPROTOTYPE, "EPROTOTYPE"},
        {EHOSTUNREACH, "EHOSTUNREACH"},                         {EINPROGRESS, "EINPROGRESS"},

    };
    std::stringstream result;
    auto find = errorString.find(errno);
    char const* errorName = find == errorString.end() ? "Unknown" : find->second;
    result << "ConnectionType::FileDescriptor: errno=" << errno << "(" << errorName << "): msg: " << strerror(errno) << ":";
    return result.str();
}
