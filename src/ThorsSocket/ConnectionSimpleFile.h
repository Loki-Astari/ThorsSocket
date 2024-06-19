#ifndef THORSANVIL_THORSSOCKET_CONNECTION_FILE_H
#define THORSANVIL_THORSSOCKET_CONNECTION_FILE_H

#include "ThorsSocketConfig.h"
#include "SocketUtil.h"
#include "ConnectionFileDescriptor.h"
#include <string>

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class SimpleFile: public FileDescriptor
{
    int fd;
    public:
        SimpleFile(FileInfo const& fileInfo, Blocking blocking);
        SimpleFile(int fd);
        virtual ~SimpleFile();

        virtual bool isConnected()                          const   override;
        virtual int  socketId(Mode mode)                    const   override;
        virtual void close()                                        override;

        virtual int getReadFD()                             const   override;
        virtual int getWriteFD()                            const   override;
        virtual void release()                                      override;
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "ConnectionSimpleFile.source"
#endif

#endif
