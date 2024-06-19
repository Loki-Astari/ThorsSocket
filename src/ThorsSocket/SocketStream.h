#ifndef THORSANVIL_THORSSOCKET_SOCKET_STREAM_H
#define THORSANVIL_THORSSOCKET_SOCKET_STREAM_H

#include "ThorsSocketConfig.h"
#include "SocketStreamBuffer.h"

namespace ThorsAnvil::ThorsSocket
{

class SocketStream: public std::iostream
{
    SocketStreamBuffer  buffer;

    public:
        SocketStream(PipeInfo const& info);
        SocketStream(FileInfo const& info);
        SocketStream(SocketInfo const& info);
        SocketStream(SSocketInfo const& info);
        SocketStream(SocketStream const&)                       = delete;
        SocketStream(SocketStream&& move) noexcept;
        ~SocketStream()                                         = default;

        SocketStream& operator=(SocketStream const&)            = delete;
        SocketStream& operator=(SocketStream&& move) noexcept   = delete;

        // Usefult for testing
        Socket& getSocket() {return buffer.getSocket();}
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "SocketStream.source"
#endif

#endif
