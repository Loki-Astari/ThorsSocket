#include "ConnectionSocketPipe.h"

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

THORS_SOCKET_HEADER_ONLY_INCLUDE
ConnectionSocketPipe::ConnectionSocketPipe()
{
    [[maybe_unused]] static const bool initDone = ConnectionSocketPipe::initializePipeSignal();
}

THORS_SOCKET_HEADER_ONLY_INCLUDE
bool ConnectionSocketPipe::initializePipeSignal()
{
    if (::signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        ThorsLogAndThrowError(std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::ConnectionSocketPipe", "initializePipeSignal", "Failed to disale SIGPIPE handling. Writing to a bad pipe will kill the processes");
    }
    return true;
}
