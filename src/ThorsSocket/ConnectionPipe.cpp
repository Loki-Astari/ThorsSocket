#include "ConnectionPipe.h"
#include "ThorsLogging/ThorsLogging.h"

#include <fcntl.h>
#include <unistd.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

Pipe::Pipe(Blocking blocking)
{
    int result = MOCK_FUNC(thorCreatePipe)(fd);
    if (result == -1)
    {
        ThorsLogAndThrow(
            "ThorsAnvil::ThorsSocket::ConnectionType::Pipe",
            "Pipe",
            " :Failed to open.",
            " errno = ", errno, " ", getErrNoStrUnix(errno),
            " msg >", getErrMsgUnix(errno), "<"
        );
    }
    if (blocking == Blocking::No)
    {
        int result = MOCK_FUNC(thorSetFDNonBlocking)(fd[0]);
        if (result == 0) {
            result = MOCK_FUNC(thorSetFDNonBlocking)(fd[1]);
        }
        if (result != 0)
        {
            close();
            ThorsLogAndThrow(
                "ThorsAnvil::ThorsSocket::ConnectionType::Pipe",
                "Pipe",
                " :Failed to set non blocking.",
                " errno = ", errno, " ", getErrNoStrUnix(errno),
                " msg >", getErrMsgUnix(errno), "<"
            );
        }
    }
}

Pipe::Pipe(int fdP[])
{
    fd[0] = fdP[0];
    fd[1] = fdP[1];
}

Pipe::~Pipe()
{
    if (isConnected()) {
        close();
    }
}

bool Pipe::isConnected() const
{
    return fd[0] != -1 || fd[1] != -1;
}

int Pipe::socketId(Mode rw) const
{
    return rw == Mode::Read ? fd[0] : fd[1];
}

void Pipe::close()
{
    MOCK_FUNC(close)(fd[0]);
    MOCK_FUNC(close)(fd[1]);
    fd[0] = -1;
    fd[1] = -1;
}

int Pipe::getReadFD() const
{
    return fd[0];
}

int Pipe::getWriteFD() const
{
    return fd[1];
}
