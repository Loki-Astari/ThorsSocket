#if 0
#include "ConnectionPipe.h"
#include "ThorsLogging/ThorsLogging.h"

#include <fcntl.h>
#include <unistd.h>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

Pipe::Pipe(Blocking blocking)
{
    int result = MOCK_FUNC(pipe)(fd);
    if (result == -1) {
        ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Pipe", "Pipe: open failed. ", buildErrorMessage());
    }
    if (blocking == Blocking::No)
    {
        int result1 = MOCK_TFUNC(fcntl)(fd[0], F_SETFL, O_NONBLOCK);
        int result2 = MOCK_TFUNC(fcntl)(fd[1], F_SETFL, O_NONBLOCK);
        if (result1 != 0 || result2 != 0)
        {
            close();
            ThorsLogAndThrowAction(ERROR, std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Pipe", "Pipe: Set non blocking. ", buildErrorMessage());
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
#endif
