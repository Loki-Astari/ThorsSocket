#ifndef THORSANVIL_TEST_CONNECTION_PIPE_H
#define THORSANVIL_TEST_CONNECTION_PIPE_H

#include "test/ConnectionFileTest.h"

class  MockConnectionPipe: public MockConnectionFile
{
    MOCK_MEMBER(pipe);

    public:
        MockConnectionPipe()
            : MOCK_PARAM(pipe,            [&](int* p)       {p[0] = 12; p[1] =13;checkExpected("pipe");return 0;})
        {}
        static ThorsAnvil::BuildTools::Mock::MockAction getActionPipeBlocking()
        {
            return {
                        "Pipe",
                        {"pipe"},
                        {"close", "close"},
                        {},
                        {}
                   };
        }
        static ThorsAnvil::BuildTools::Mock::MockAction getActionPipeNonBlocking()
        {
            return {
                        "Pipe",
                        {"pipe", "fcntl", "fcntl"},
                        {"close", "close"},
                        {},
                        {}
                   };
        }
};

#endif
