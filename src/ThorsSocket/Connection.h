#ifndef THORSANVIL_THORSSOCKET_CONNECTION_H
#define THORSANVIL_THORSSOCKET_CONNECTION_H

#include "ThorsSocketConfig.h"
#include "SocketUtil.h"
#include <memory>
#include <string>
#include <cstddef>

namespace ThorsAnvil::ThorsSocket
{

class Connection
{
    public:
        Connection()            {}
        virtual ~Connection()   {}
        Connection(Connection const&)                               = delete;
        Connection& operator=(Connection const&)                    = delete;

        virtual bool isConnected()                          const   = 0;
        virtual int  socketId(Mode)                         const   = 0;
        virtual void close()                                        = 0;
        virtual void tryFlushBuffer()                               = 0;

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)             = 0;
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)   = 0;

        virtual std::string errorMessage()                          = 0;
};

}

#endif
