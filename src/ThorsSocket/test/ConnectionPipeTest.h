#ifndef THORSANVIL_TEST_CONNECTION_PIPE_H
#define THORSANVIL_TEST_CONNECTION_PIPE_H

#include "test/ConnectionFileTest.h"

class  MockConnectionPipe: public MockConnectionFile
{
    int count;
    MOCK_MEMBER(pipe);

    public:
        MockConnectionPipe()
            : count(0)
            , MOCK_PARAM(pipe,            [&](int* p)       {++count;p[0] = 12; p[1] =13;std::cerr << "Unexpected: pipe\n";return 0;})
        {}
        int callCount() const {return MockConnectionFile::callCount() + count;}
};

#endif
