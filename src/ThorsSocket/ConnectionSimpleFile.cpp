#include "ConnectionSimpleFile.h"
#include "ConnectionUtil.h"
#include "ThorsLogging/ThorsLogging.h"

#include <fcntl.h>
#include <unistd.h>
#include <iostream>


using namespace ThorsAnvil::ThorsSocket::ConnectionType;

THORS_SOCKET_HEADER_ONLY_INCLUDE
int convertModeToOpenFlag(ThorsAnvil::ThorsSocket::FileMode mode, ThorsAnvil::ThorsSocket::Blocking blocking)
{
    int result = THOR_BINARY;
    result |= (blocking == ThorsAnvil::ThorsSocket::Blocking::No ? NONBLOCKING_FLAG : 0);
    switch (mode)
    {
        case ThorsAnvil::ThorsSocket::FileMode::Read:          return result | O_RDONLY;
        case ThorsAnvil::ThorsSocket::FileMode::WriteTruncate: return result | O_WRONLY | O_CREAT | O_TRUNC;
        case ThorsAnvil::ThorsSocket::FileMode::WriteAppend:   return result | O_WRONLY | O_CREAT | O_APPEND;
    }
    return 0;
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
SimpleFile::SimpleFile(FileInfo const& fileInfo, Blocking blocking)
    : fd(MOCK_TFUNC(open)(&fileInfo.fileName[0], convertModeToOpenFlag(fileInfo.mode, blocking), 0777))
{
    if (fd == -1)
    {
        ThorsLog(
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
