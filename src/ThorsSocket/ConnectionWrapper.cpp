#include "ConnectionWrapper.h"

#ifdef __WINNT__

int pipe(int fildes[2])
{
    return _pipe(fildes, 256, O_BINARY);
}
int fcntl(int /*fd*/, int /*cmd*/, int /*flag*/)
{
    // Non Blocking pipe and files are not supported on Windows
    return -1;
}

#endif
