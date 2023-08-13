#ifndef THORSANVIL_THORSSOCKET_MOCKABLE_OS_FUNCTION_H
#define THORSANVIL_THORSSOCKET_MOCKABLE_OS_FUNCTION_H

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>

inline int open_mockable(const char *pathname, int flags, mode_t mode)          {return ::open(pathname, flags, mode);}
inline int close_mockable(int fd)                                               {return ::close(fd);}
inline int shutdown_mockable(int fd, int how)                                   {return ::shutdown(fd, how);}
inline int read_mockable(int fd, void* buffer, size_t size)                     {return ::read(fd, buffer, size);}
inline int write_mockable(int fd, const void* buffer, size_t size)              {return ::write(fd, buffer, size);}

#endif
