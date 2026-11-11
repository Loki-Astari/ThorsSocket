#ifndef THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_PIPE_H
#define THORSANVIL_THORSSOCKET_CONNECTION_SOCKET_PIPE_H

#include "ThorsSocketConfig.h"
#include "ConnectionFileDescriptor.h"

#include  <cstddef>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class ConnectionSocketPipe: public FileDescriptor
{
    static bool initializePipeSignal();
    public:
        ConnectionSocketPipe();
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "ConnectionSocketPipe.source"
#endif

#endif
