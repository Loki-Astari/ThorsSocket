#ifndef THORSANVIL_THORSSOCKET_SOCKET_UTIL_H
#define THORSANVIL_THORSSOCKET_SOCKET_UTIL_H

#include <cstddef>
#include <utility>
#include <stdexcept>
#include <sys/types.h>

namespace ThorsAnvil::ThorsSocket
{

struct IOData
{
    std::size_t     dataSize;
    bool            stillOpen;
    bool            blocked;
};

struct SocketCritical: public std::logic_error
{
    using std::logic_error::logic_error;
};
struct SocketUnknown: public std::runtime_error
{
    using std::runtime_error::runtime_error;
};


#if 0
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
#endif

enum class Open     {Append, Truncate};
enum class Blocking {No, Yes};
enum class Mode     {Read, Write};

}

#endif
