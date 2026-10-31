#ifndef THORSANVIL_THORSSOCKET_CONNECTION_EXECUTABLE_H
#define THORSANVIL_THORSSOCKET_CONNECTION_EXECUTABLE_H

#include "ThorsSocketConfig.h"
#include "ConnectionFileDescriptor.h"

namespace ThorsAnvil::ThorsSocket::ConnectionType
{

class Executable: public FileDescriptor
{
    public:
        // Normal Client.
        Executable(ExecutableFile executable, Blocking blocking);
        virtual ~Executable();

        // ConnectionBase
        virtual int  socketId(Mode mode)                    const   override {return mode == Mode::Write ? childIn : childOut;}
        virtual bool isConnected()                          const   override {return procId != 0;}
        virtual void close()                                        override;
        virtual void release()                                      override;

        // ConnectionClient
        virtual std::string_view protocol()                 const   override {using namespace std::string_view_literals;return "exe"sv;}

        // FileDescriptor
        virtual int getReadFD()                             const   override {return childOut;}  // We read from the applications std::cout
        virtual int getWriteFD()                            const   override {return childIn;}   // We read from the applications std::cin
    private:
        int     procId;
        int     childIn;
        int     childOut;
};

}

#if THORS_SOCKET_HEADER_ONLY
#include "ConnectionExecutable.source"
#endif

#endif
