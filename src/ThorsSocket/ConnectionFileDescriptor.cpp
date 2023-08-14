#include "ConnectionFileDescriptor.h"

#include <map>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

using namespace ThorsAnvil::ThorsSocket;

ConnectionFileDescriptor::ConnectionFileDescriptor(std::string const& fileName, Type type, Blocking blocking)
    : fd(MOCK_FUNC(open)(fileName.c_str(),
                       (type == Type::Append ? O_APPEND : O_TRUNC) | O_CREAT | (blocking == Blocking::No ? O_NONBLOCK : 0),
                       O_RDWR))
{}

ConnectionFileDescriptor::ConnectionFileDescriptor(int fd)
    : fd(fd)
{}

ConnectionFileDescriptor::~ConnectionFileDescriptor()
{
    if (isConnected()) {
        close();
    }
}

bool ConnectionFileDescriptor::isConnected() const
{
    return fd != -1;
}

int ConnectionFileDescriptor::socketId() const
{
    return fd;
}

void ConnectionFileDescriptor::close()
{
    MOCK_FUNC(close)(fd);
    fd = -1;
}

void ConnectionFileDescriptor::tryFlushBuffer()
{
    // Does nothing for files.
}

IOResult ConnectionFileDescriptor::read(char* buffer, std::size_t size, std::size_t dataRead)
{
    while (dataRead != size)
    {
        ssize_t chunkRead = MOCK_FUNC(read)(fd, buffer + dataRead, size - dataRead);
        if (chunkRead == -1)
        {
            // 1: https://man7.org/linux/man-pages/man2/read.2.html
            // 2: https://www.ibm.com/docs/en/zvse/6.2?topic=SSB27H_6.2.0/fa2ti_call_read.htm
            // 3: https://linux.die.net/man/3/read
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

IOResult ConnectionFileDescriptor::write(char const* buffer, std::size_t size, std::size_t dataWritten)
{
    while (dataWritten != size)
    {
        ssize_t chunkWritten = MOCK_FUNC(write)(fd, buffer + dataWritten, size - dataWritten);
        if (chunkWritten == -1)
        {
            // 1: https://man7.org/linux/man-pages/man2/write.2.html
            // 2: https://www.ibm.com/docs/en/zvse/6.2?topic=SSB27H_6.2.0/fa2ti_call_write.htm
            // 3: https://linux.die.net/man/3/write
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

std::string ConnectionFileDescriptor::errorMessage()
{
    static const std::map<int, char const*> errorString =
    {
        {EOVERFLOW, "EOVERFLOW"},       {EBADF, "EBADF"},   {EFAULT, "EFAULT"}, {EINVAL, "EINVAL"},
        {EBADMSG, "EBADMSG"},           {ENXIO, "ENXIO"},   {ESPIPE, "ESPIPE"}, {EINTR, "EINTR"},
        {ECONNRESET, "ECONNRESET"},     {EAGAIN, "EAGAIN"}, {EISDIR, "EISDIR"}, /* {EWOULDBLOC, "EWOULDBLOC"}, */
        {ENOTCONN, "ENOTCONN"},         {ENOBUFS, "ENOBUFS"},{EIO, "EIO"},      {ENOMEM, "ENOMEM"},
        {ETIMEDOUT, "ETIMEDOUT"},       {ENOSPC, "ENOSPC"}, {EPERM, "EPERM"},   {EPIPE, "EPIPE"},
        {EDESTADDRREQ, "EDESTADDRREQ"}, {EDQUOT, "EDQUOT"}, {EFBIG, "EFBIG"},   {ERANGE, "ERANGE"},
        {ENETUNREACH, "ENETUNREACH"},   {ENETDOWN, "ENETDOWN"}
    };
    std::stringstream result;
    auto find = errorString.find(errno);
    char const* errorName = find == errorString.end() ? "Unknown" : find->second;
    result << "ConnectionFileDescriptor: errno=" << errno << "(" << errorName << "): msg: " << strerror(errno) << ":";
    return result.str();
}
