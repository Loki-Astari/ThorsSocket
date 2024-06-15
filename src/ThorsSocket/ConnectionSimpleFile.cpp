#include "ConnectionSimpleFile.h"
#include "ThorsLogging/ThorsLogging.h"

#include <fcntl.h>
#include <unistd.h>


using namespace ThorsAnvil::ThorsSocket::ConnectionType;

THORS_SOCKET_HEADER_ONLY_INCLUDE
SimpleFile::SimpleFile(std::string const& fileName, Open open, Blocking blocking)
    : fd(MOCK_TFUNC(open)(fileName.c_str(),
                       (open == Open::Append ? O_APPEND : O_TRUNC) | O_CREAT | (blocking == Blocking::No ? NONBLOCKING_FLAG : 0),
                       O_RDWR))
{
    if (fd == -1)
    {
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::SimpleFile",
            "SimpleFile",
            " :Failed to open.",
            " errno = ", errno, " ", getErrNoStrUnix(errno),
            " msg >", getErrMsgUnix(errno), "<"
        );
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SimpleFile::SimpleFile(int fd)
    : fd(fd)
{}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SimpleFile::~SimpleFile()
{
    if (isConnected()) {
        close();
    }
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool SimpleFile::isConnected() const
{
    return fd != -1;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SimpleFile::socketId(Mode) const
{
    // Both read and write use same ID
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SimpleFile::close()
{
    MOCK_FUNC(close)(fd);
    fd = -1;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SimpleFile::getReadFD() const
{
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
int SimpleFile::getWriteFD() const
{
    return fd;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
void SimpleFile::release()
{
    fd = -1;
}
