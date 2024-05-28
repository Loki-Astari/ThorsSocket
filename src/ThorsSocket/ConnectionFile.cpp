#include "ConnectionFile.h"
#include "ThorsLogging/ThorsLogging.h"

#include <fcntl.h>
#include <unistd.h>


using namespace ThorsAnvil::ThorsSocket::ConnectionType;

File::File(std::string const& fileName, Open open, Blocking blocking)
    : fd(MOCK_TFUNC(open)(fileName.c_str(),
                       (open == Open::Append ? O_APPEND : O_TRUNC) | O_CREAT | (blocking == Blocking::No ? NONBLOCKING_FLAG : 0),
                       O_RDWR))
{
    if (fd == -1)
    {
        ThorsLogAndThrowAction(
            ERROR,
            std::runtime_error,
            "ThorsAnvil::ThorsSocket::ConnectionType::File",
            "File",
            " :Failed to open.",
            " errno = ", errno, " ", getErrNoStrUnix(errno),
            " msg >", getErrMsgUnix(errno), "<"
        );
    }
}

File::File(int fd)
    : fd(fd)
{}

File::~File()
{
    if (isConnected()) {
        close();
    }
}

bool File::isConnected() const
{
    return fd != -1;
}

int File::socketId(Mode) const
{
    // Both read and write use same ID
    return fd;
}

void File::close()
{
    MOCK_FUNC(close)(fd);
    fd = -1;
}

int File::getReadFD() const
{
    return fd;
}

int File::getWriteFD() const
{
    return fd;
}
