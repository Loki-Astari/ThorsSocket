#ifndef THORSANVIL_TEST_CONNECTION_FILE_H
#define THORSANVIL_TEST_CONNECTION_FILE_H

#include "test/ConnectionFileDescriptorTest.h"

class MockConnectionFile: public MockConnectionFileDescriptor
{
    MOCK_TMEMBER(OpenType, open);
    MOCK_MEMBER(close);
    MOCK_TMEMBER(FctlType, fcntl);

    public:
        MockConnectionFile()
            : MOCK_PARAM(open,      [&](char const*, int, int)  {return 12;})
            , MOCK_PARAM(close,     [&](int)                    {return 0;})
            , MOCK_PARAM(fcntl,     [&](int, int, int)          {return 0;})
        {}

        static ThorsAnvil::BuildTools::Mock::MockAction getActionFile()
        {
            return {
                        "File",
                        {"open"},
                        {"close"},
                        {},
                        {}
                   };
        }
};

#endif
