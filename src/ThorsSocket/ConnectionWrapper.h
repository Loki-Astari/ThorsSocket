#ifndef THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H
#define THORSANVIL_THORSSOCKET_CONNECTION_WRAPPER_H

#ifdef  __WINNT__
int pipe(int fildes[2]);
int fcntl(int /*fd*/, int /*cmd*/, int /*flag*/);
#else
#endif

#endif
