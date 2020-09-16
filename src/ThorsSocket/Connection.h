#ifndef THORS_ANVIL_DB_CONNECTION_H
#define THORS_ANVIL_DB_CONNECTION_H

#include <cstddef>

namespace ThorsAnvil::ThorsIO
{

class Connection
{
    public:
        virtual void accept();
        virtual void connect();
        virtual int read(char* buffer, std::size_t len);
        virtual int write(char const* buffer, std::size_t len);
        virtual int errorCode(int ret);
};

}

#endif
