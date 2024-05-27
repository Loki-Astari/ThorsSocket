#ifndef THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H
#define THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H


#ifdef  __WINNT__

#define NONBLOCKING_FLAG        0
#define SETBLOCKING_CMD         0
#define PAUSE_AND_WAIT(n)       Sleep(n * 1000)

int pipe(int fildes[2]);
int fcntl(int /*fd*/, int /*cmd*/, int /*flag*/);

#else

#define SETBLOCKING_CMD         F_SETFL
#define NONBLOCKING_FLAG        O_NONBLOCK
#define PAUSE_AND_WAIT(n)       sleep(n)
#endif

#endif
