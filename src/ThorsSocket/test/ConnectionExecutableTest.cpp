#include <gtest/gtest.h>
#include "ConnectionExecutable.h"
#include "MockHeaderInclude.h"
#include "SocketStream.h"
#include "SocketUtil.h"

#include <string>

namespace ThorsAnvil::BuildTools::Mock
{

TA_Object   Executable_Executable_NormalConstruction(
                build()
                .expectInitTA(thorCreatePipe)// .toReturn(0)
                .expectInitTA(thorCreatePipe)// .toReturn(0)
                .expectInitTA(fork)//.toReturn(32)
                .expectDestTA(close)//.checkInput(13)
                .expectDestTA(close)//.checkInput(12)
                .expectDestTA(kill)//.checkInput(32, SIGKILL)
                .expectDestTA(waitpid)//.checkInput(32, nullptr, 0)
            );
}

using ThorsAnvil::ThorsSocket::ExecutableFile;
using ThorsAnvil::ThorsSocket::SocketStream;

TEST(ConnectionExecutableTest, CheckOutput)
{
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    // see ConnectionUtil.cpp
    GTEST_SKIP();
#endif
    SocketStream      executable(ExecutableFile{"/bin/bash", {"-c", "ls"}});
    std::string line;

    int count = 0;
    while (std::getline(executable, line)) {
        ++count;
    }
    ASSERT_NE(0, count);
}

TEST(ConnectionExecutableTest, CheckInput)
{
#ifdef __WINNT__
    // Windows does not support non blocking pipes
    // So this test will fail.
    // see ConnectionUtil.cpp
    GTEST_SKIP();
#endif
    SocketStream      executable(ExecutableFile{"/bin/bash", {"-c", "bc"}});
    executable << "5+4\n" << std::flush;

    std::string line;
    std::getline(executable, line);

    ASSERT_EQ("9", line);
}

