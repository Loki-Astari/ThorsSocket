#ifndef THORSANVIL_THORSSOCKET_CONNECTION_FILE_DESCRIPTOR_H
#define THORSANVIL_THORSSOCKET_CONNECTION_FILE_DESCRIPTOR_H

#include "ThorsSocketConfig.h"
#include "Connection.h"
#include "MockableOSFunction.h"

namespace ThorsAnvil::ThorsSocket
{

enum class Type {Append, Truncate};
enum class Blocking {No, Yes};
class ConnectionFileDescriptor: public Connection
{
    int fd;
    public:
        ConnectionFileDescriptor(std::string const& fileName, Type type, Blocking blocking);
        ConnectionFileDescriptor(int fd);
        virtual ~ConnectionFileDescriptor();

        virtual bool isConnected()                          const   override;
        virtual int  socketId()                             const   override;
        virtual void close()                                        override;
        virtual void tryFlushBuffer()                               override;

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)             override;
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)   override;

        virtual std::string errorMessage()                          override;
};

}

#endif
