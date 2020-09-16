#include "Connection.h"

using namespace ThorsAnvil::ThorsIO;

void Connection::accept()
{
}

void Connection::connect()
{
}

int Connection::read(char* /*buffer*/, std::size_t /*len*/)
{
    return 0;
}

int Connection::write(char const* /*buffer*/, std::size_t /*len*/)
{
    return 0;
}

int Connection::errorCode(int /*ret*/)
{
    return 0;
}
