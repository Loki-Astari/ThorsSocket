#ifndef THORSANVIL_THORSSOCKET_CONNECTION_FILE_DESCRIPTOR_H
#define THORSANVIL_THORSSOCKET_CONNECTION_FILE_DESCRIPTOR_H

#include "ThorsSocketConfig.h"
#include "Connection.h"

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class FileDescriptor: public Connection
{
    public:
        virtual void tryFlushBuffer()                               override;

        virtual IOResult read(char* buffer, std::size_t size, std::size_t read)             override;
        virtual IOResult write(char const* buffer, std::size_t size, std::size_t written)   override;

        virtual std::string errorMessage()                          override;

        static std::string buildErrorMessage();
    protected:
        virtual int getReadFD()                             const = 0;
        virtual int getWriteFD()                            const = 0;
};

}

#endif
