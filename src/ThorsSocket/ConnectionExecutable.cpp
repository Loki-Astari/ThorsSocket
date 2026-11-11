#include "ConnectionExecutable.h"
#include "ConnectionUtil.h"

#include <sys/_types/_pid_t.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
// #include <sys/prctl.h>
#include <stdlib.h>
// #include <string.h>
#include <stdio.h>

#include <iostream>

using namespace ThorsAnvil::ThorsSocket::ConnectionType;

Executable::Executable(ExecutableFile executable, Blocking blocking)
    : FileDescriptor{}
    , procId{0}
    , childIn{0}
    , childOut{0}
{
#ifdef  __WINNT__
    ThorsLogAndThrowDebug(std::runtime_error,"ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "This has not been tested on Windows");
#else

    int parentToChild[2];
    if (MOCK_FUNC(thorCreatePipe)(parentToChild) != 0) {
        ThorsLogAndThrowDebug(std::runtime_error,"ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "pipe() for input stream failed: errno = ", errno, " msg >", getErrMsgUnix(errno), "<");
    }
    int childToParent[2];
    if (MOCK_FUNC(thorCreatePipe)(childToParent) != 0) {
        MOCK_FUNC(close)(parentToChild[1]);
        MOCK_FUNC(close)(parentToChild[0]);
        ThorsLogAndThrowDebug(std::runtime_error,"ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "pipe() for output stream failed: errno = ", errno, " msg >", getErrMsgUnix(errno), "<");
    }

    procId = MOCK_FUNC(fork)();
    if (procId == -1) {
        MOCK_FUNC(close)(childToParent[1]);
        MOCK_FUNC(close)(childToParent[0]);
        MOCK_FUNC(close)(parentToChild[1]);
        MOCK_FUNC(close)(parentToChild[0]);
        ThorsLogAndThrowDebug(std::runtime_error,"ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "fork() of child failed: errno = ", errno, " msg >", getErrMsgUnix(errno), "<");
    }
    if (blocking == Blocking::No)
    {
        int result = MOCK_FUNC(thorSetFDNonBlocking)(parentToChild[0])
                ||   MOCK_FUNC(thorSetFDNonBlocking)(parentToChild[1])
                ||   MOCK_FUNC(thorSetFDNonBlocking)(childToParent[0])
                ||   MOCK_FUNC(thorSetFDNonBlocking)(childToParent[1]);
        if (result != 0)
        {
            MOCK_FUNC(close)(childToParent[1]);
            MOCK_FUNC(close)(childToParent[0]);
            MOCK_FUNC(close)(parentToChild[1]);
            MOCK_FUNC(close)(parentToChild[0]);
            ThorsLogAndThrowDebug(
                std::runtime_error,
                "ThorsAnvil::ThorsSocket::ConnectionType::Executable",
                "Executable",
                " :Failed to set non blocking.",
                " errno = ", errno, " ", getErrNoStrUnix(errno),
                " msg >", getErrMsgUnix(errno), "<"
            );
        }
    }
    if (procId != 0)
    {
        // This is the parent processes.
        // So lets set the members correctly and get out of here.
        childIn = parentToChild[1];
        childOut = childToParent[0];
        MOCK_FUNC(close)(parentToChild[0]);
        MOCK_FUNC(close)(childToParent[1]);

        ThorsLogTrack("ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "Parent: The child processes created: ", executable.fileName);
        return;
    }

    // This is the child processes
    // connect the streams to stdin/stdout
    MOCK_FUNC(dup2)(parentToChild[0], STDIN_FILENO);
    MOCK_FUNC(dup2)(childToParent[1], STDOUT_FILENO);
    // We are not connecting the stderr as this is used for logging.
    //dup2(inpipefd[1], STDERR_FILENO);

    // ask kernel to deliver SIGTERM in case the parent dies
    // prctl(PR_SET_PDEATHSIG, SIGTERM);

    // close unused pipe ends
    MOCK_FUNC(close)(parentToChild[1]);
    MOCK_FUNC(close)(parentToChild[0]);
    MOCK_FUNC(close)(childToParent[1]);
    MOCK_FUNC(close)(childToParent[0]);

    // Convert arguments into expected format for execv function.
    std::vector<char*>     args;
    auto find = executable.fileName.find_last_of('/');
    args.emplace_back(&(executable.fileName[0]) + (find == std::string::npos ? 0 : find + 1));
    for (auto& a: executable.arguments) {
        args.emplace_back(&a[0]);
    }
    args.emplace_back(nullptr);

    // Replace this processes with the executable we want.
    ThorsLogTrack("ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "Child: about to exec the processes: ", executable.fileName);
    MOCK_FUNC(execv)(executable.fileName.c_str(), args.data());
    ThorsLogAlert("ThorsAnvil::ThorsSocket::ConnectionType::Executable", "Executable", "Child: failed to start child processes. errno=", errno, " msg >" << getErrMsgUnix(errno) << "<");

    // Nothing below this line should be executed by child process.
    // If we get here it means that the execl function wasn't successful.
    // So lets clean up and exit.
    // Remember this is the child processes.
    exit(1);
#endif
}

Executable::~Executable()
{
    if (procId != 0) {
        close();
    }
}

void Executable::close()
{
    MOCK_FUNC(kill)(procId, SIGKILL); //send SIGKILL signal to the child process

    int status = 25;
    int x = MOCK_FUNC(waitpid)(procId, &status, 0);
    procId = 0;

    MOCK_FUNC(close)(childOut);
    childOut = -1;
    MOCK_FUNC(close)(childIn);
    childIn = -1;
}

void Executable::release()
{
    ThorsLogAndThrowError(std::runtime_error, "ThorsAnvil::ThorsSocket::ConnectionType::Executable", "release", "Can't release an executable");
}
