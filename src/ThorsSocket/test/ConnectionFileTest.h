#ifndef THORSANVIL_TEST_CONNECTION_FILE_H
#define THORSANVIL_TEST_CONNECTION_FILE_H

#include "test/ConnectionFileDescriptorTest.h"

class MockConnectionFile: public MockConnectionFileDescriptor
{
    int count;
    MOCK_MEMBER(close);
    MOCK_TMEMBER(FctlType, fcntl);

    public:
        MockConnectionFile()
            : count(0)
            , MOCK_PARAM(close,            [&](int)             {++count;std::cerr << "Unexpected: close\n";return 0;})
            , MOCK_PARAM(fcntl,            [&](int, int, int)   {++count;std::cerr << "Unexpected: fcntl\n";return 0;})
        {}
        int callCount() const {return MockConnectionFileDescriptor::callCount() + count;}
};

#endif
