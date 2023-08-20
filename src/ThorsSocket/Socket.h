#ifndef THORSANVIL_THORSSOCKET_SOCKET_H
#define THORSANVIL_THORSSOCKET_SOCKET_H

#include "ThorsSocketConfig.h"

#include <memory>
#include <functional>

namespace ThorsAnvil::ThorsSocket
{

class Connection;
class SocketBuilder;
using IOData    = std::pair<bool, std::size_t>;

class Socket
{
    std::unique_ptr<Connection>     connection;
    std::function<void()>           readYield;
    std::function<void()>           writeYield;

    private:
        friend class SocketBuilder;
        Socket(std::unique_ptr<Connection>&& connection, std::function<void()>&& readYield, std::function<void()>&& writeYield);

    public:
        Socket(Socket&& move)               noexcept;
        Socket& operator=(Socket&& move)    noexcept;

        void swap(Socket& other)            noexcept;

        Socket(Socket const&)               = delete;
        Socket& operator=(Socket const&)    = delete;

        bool isConnected()                  const;
        int  socketId()                     const;      // Only useful for unit tests

        IOData getMessageData(void* buffer, std::size_t size);
        IOData putMessageData(void const* buffer, std::size_t size);

        void tryFlushBuffer();

        void close();
};
void swap(Socket& lhs, Socket& rhs);

class SocketBuilder
{
    std::unique_ptr<Connection>     connection;
    std::function<void()>           readYield   = [](){};
    std::function<void()>           writeYield  = [](){};

    public:
        template<typename Connection, typename... Args>
        SocketBuilder& addConnection(Args&&... args)
        {
            connection = std::make_unique<Connection>(std::forward<Args>(args)...);
            return *this;
        }
        template<typename F>
        SocketBuilder& addReadYield(F&& func)
        {
            readYield = std::forward<F>(func);
            return *this;
        }
        template<typename F>
        SocketBuilder& addwriteYield(F&& func)
        {
            writeYield = std::forward<F>(func);
            return *this;
        }

        Socket build();
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "Socket.source"
#endif

#endif
