#ifndef THORSANVIL_THORSSOCKET_CONNECTION_H
#define THORSANVIL_THORSSOCKET_CONNECTION_H

#include "ThorsSocketConfig.h"
#include <memory>
#include <functional>
#include <string>
#include <cstddef>

namespace ThorsAnvil::ThorsSocket
{

enum class Result
{
    OK,                     // Read / Write OK

    CriticalBug,            // This wrapper is supposed to prevent these type of issues from happening.
                            // If reported this is an application stopping issue.
                            // ThorsLogAndThrowFatal
                            //      Exception:   ThorsAnvil::Logging::FatalException

    Interupt,               // OS interrupted the operation.
                            // The socket will simply retry the operation.

    ConnectionClosed,       // Can no longer read from the socket.
                            // The operation will return immediately indicating an error and the
                            // amount of data that was processed.

    WouldBlock,             // A non blocking stream.
                            // There is no data available. A blocking stream would block.
                            // call the yieldMethod() then retry.
                            // Can be used in conjuntion with an event library to schedule other work.

    Unknown                 // No specific error handling exists
                            // ThorsLogAndThrow
                            //      Exception   std::runtime_error
};

/*
 * IOInfo:      amount of data read/written + OS specific error code.
 *
 * IOResult:    Interface to socket for read/write.
 */
using IOInfo            = std::pair<ssize_t, int>;
using IOResult          = std::pair<ssize_t, Result>;


class Connection
{
    public:
        Connection()            {}
        virtual ~Connection()   {}
        Connection(Connection const&)                               = delete;
        Connection& operator=(Connection const&)                    = delete;

        virtual bool isConnected()                          const   = 0;
        virtual int  socketId()                             const   = 0;
        virtual void close()                                        = 0;
        virtual void tryFlushBuffer()                               = 0;

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)             = 0;
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)   = 0;

        virtual std::string errorMessage()                          = 0;
};

}

#endif
