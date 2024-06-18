#ifndef THORSANVIL_THORSSOCKET_SOCKET_STREAM_H
#define THORSANVIL_THORSSOCKET_SOCKET_STREAM_H

#include "ThorsSocketConfig.h"
#include "Socket.h"
#include <iostream>

namespace ThorsAnvil::ThorsSocket
{

class SocketStream: public std::iostream
{
    class SocketStreamBuffer: std::basic_streambuf
    {
        Socket                  socket;
        std::vector<char>       inputBuffer;
        std::vector<char>       outputBuffer;
        public:
            SocketStreamBuffer(SocketInfo const& info);
    };

    public:
        SocketStream(SocketInfo const& info);
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "SocketStream.source"
#endif

#endif
