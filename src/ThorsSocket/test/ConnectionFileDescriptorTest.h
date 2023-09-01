#ifndef THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H
#define THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

class MockConnectionFileDescriptor
{
    int count;
    MOCK_MEMBER(read);
    MOCK_MEMBER(write);

    public:
        MockConnectionFileDescriptor()
            : count(0)
            , MOCK_PARAM(read,            [&](int, void*, ssize_t size)             {++count;std::cerr << "Unexpected: read\n";return size;})
            , MOCK_PARAM(write,           [&](int, void const*, ssize_t size)       {++count;std::cerr << "Unexpected: write\n";return size;})
        {}
        int callCount() const {return count;}
};

#endif
