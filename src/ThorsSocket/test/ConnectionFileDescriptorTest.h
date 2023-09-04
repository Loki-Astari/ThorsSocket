#ifndef THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H
#define THORSANVIL_TEST_CONNECTION_FILE_DESCRIPTOR_H

#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

class MockConnectionFileDescriptor: public ThorsAnvil::BuildTools::Mock::MockOverride
{
    MOCK_MEMBER(read);
    MOCK_MEMBER(write);

    public:
        MockConnectionFileDescriptor()
            : MOCK_PARAM(read,            [&](int, void*, ssize_t size)             {checkExpected("read");return size;})
            , MOCK_PARAM(write,           [&](int, void const*, ssize_t size)       {checkExpected("write");return size;})
        {}
};

#endif
