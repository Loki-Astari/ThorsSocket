#include <gtest/gtest.h>

#include "SocketUtil.h"
#include "Socket.h"

using namespace ThorsAnvil::ThorsSocket;

TEST(MoveTeat, FileInfo)
{
    FileInfo        tmp1{"File1", FileMode::Read};
    FileInfo        tmp2{"File2", FileMode::WriteAppend};

    std::swap(tmp1, tmp2);
}

TEST(MoveTeat, PipeInfo)
{
    PipeInfo        tmp1{};
    PipeInfo        tmp2{};

    std::swap(tmp1, tmp2);
}

TEST(MoveTeat, SocketInfo)
{
    SocketInfo      tmp1{"google.com", 8080};
    SocketInfo      tmp2{"github.com", 9090};

    std::swap(tmp1, tmp2);
}

TEST(MoveTeat, SocketService)
{
    SocketService   tmp1{"google.com", "https"};
    SocketService   tmp2{"github.com", "https"};

    std::swap(tmp1, tmp2);
}

TEST(MoveTeat, SSocketInfo)
{
    SSLctx          ctx1{SSLMethodType::Client};
    SSocketInfo     tmp1{"thors-anvil.com", 443, ctx1, DeferAccept::Yes};

    SSLctx          ctx2{SSLMethodType::Client};
    SSocketInfo     tmp2{"thors-bad.com", 225, ctx2, DeferAccept::No};

    std::swap(tmp1, tmp2);
}

TEST(MoveTeat, SSocketService)
{
    SSLctx          ctx1{SSLMethodType::Client};
    SSocketService  tmp1{"thors-anvil.com", "https", ctx1, DeferAccept::Yes};

    SSLctx          ctx2{SSLMethodType::Client};
    SSocketService  tmp2{"thors-bad.com", "mongo", ctx2, DeferAccept::No};

    std::swap(tmp1, tmp2);
}

TEST(MoveTest, SokcetInit)
{
    SocketInit      tmp1{SocketInfo{"google.com", 4030}};
    SSLctx          ctx{SSLMethodType::Client};
    SocketInit      tmp2{SSocketInfo{"google.com", 4035, ctx, DeferAccept::Yes}};

    std::swap(tmp1, tmp2);
}
