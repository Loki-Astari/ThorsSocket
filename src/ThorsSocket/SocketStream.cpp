#include "SocketStream.h"

using namespace ThorsAnvil::ThorsSocket;


SocketStream::SocketStream(PipeInfo const& info)
    : std::iostream(nullptr)
    , buffer(info)
{
    rdbuf(&buffer);
}

SocketStream::SocketStream(FileInfo const& info)
    : std::iostream(nullptr)
    , buffer(info)
{
    rdbuf(&buffer);
}

SocketStream::SocketStream(SocketInfo const& info)
    : std::iostream(nullptr)
    , buffer(info)
{
    rdbuf(&buffer);
}

SocketStream::SocketStream(SSocketInfo const& info)
    : std::iostream(nullptr)
    , buffer(info)
{
    rdbuf(&buffer);
}

SocketStream::SocketStream(SocketStream&& move) noexcept
    : std::iostream(nullptr)
    , buffer(std::move(move.buffer))
{
    rdbuf(&buffer);
}
