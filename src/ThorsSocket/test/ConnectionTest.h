#ifndef THORSANVIL_THORSSOCKET_TEST_CONNECTION_TEST_H
#define THORSANVIL_THORSSOCKET_TEST_CONNECTION_TEST_H

#include "Connection.h"

class TempFileWithCleanup
{
    std::string     fileName;
    public:
        TempFileWithCleanup()
            : fileName("/var/tmp/XXXXXX")
        {
            mktemp(fileName.data());
        }
        ~TempFileWithCleanup()
        {
            unlink(fileName.c_str());
        }
        operator std::string const&() {return fileName;}
};

using ThorsAnvil::ThorsSocket::Open;
using ThorsAnvil::ThorsSocket::Blocking;

#endif
