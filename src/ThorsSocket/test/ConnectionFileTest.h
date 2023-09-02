#ifndef THORSANVIL_TEST_CONNECTION_FILE_H
#define THORSANVIL_TEST_CONNECTION_FILE_H

#include "test/ConnectionFileDescriptorTest.h"

class MockConnectionFile: public MockConnectionFileDescriptor
{
    MOCK_MEMBER(close);
    MOCK_TMEMBER(FctlType, fcntl);

    public:
        MockConnectionFile()
            : MOCK_PARAM(close,            [&](int)             {checkExpected("close");return 0;})
            , MOCK_PARAM(fcntl,            [&](int, int, int)   {checkExpected("fcntl");return 0;})
        {}
};

#endif
