#ifndef THORSANVIL_THORSSOCKET_SOCKET_STREAM_H
#define THORSANVIL_THORSSOCKET_SOCKET_STREAM_H

#include "ThorsSocketConfig.h"
#include "SocketStreamBuffer.h"

#include <iostream>

namespace ThorsAnvil::ThorsSocket
{


template<typename Buffer = SocketStreamBuffer>
class SocketStream: public std::iostream
{
    Buffer  buffer;

    public:
        // Create from a socket.
        SocketStream();
        SocketStream(Socket&& socket);
        SocketStream(SocketStream&& move) noexcept;
        SocketStream& operator=(SocketStream&& move) noexcept;

        // Manual Creation.
        SocketStream(PipeInfo const& info);
        SocketStream(FileInfo const& info);
        SocketStream(SocketInfo const& info);
        SocketStream(SSocketInfo const& info);
        ~SocketStream()                                         = default;

        // No copying allowed
        SocketStream(SocketStream const&)                       = delete;
        SocketStream& operator=(SocketStream const&)            = delete;

        // Usefult for testing
        Socket&         getSocket()         {return buffer.getSocket();}
        Socket const&   getSocket() const   {return buffer.getSocket();}
};

}

#include "SocketStream.tpp"

#endif
