#ifndef THORSANVIl_THORS_SOCKET_MOCK_HEADER_INCLUDE
#define THORSANVIl_THORS_SOCKET_MOCK_HEADER_INCLUDE

#include <fcntl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "OpenSSLMacroWrappers.h"

// # Version 1
using OpenType = int(const char*, int, unsigned short);
using FctlType = int(int, int, int);

// # Version 2
using FuncType_open     = int(const char*, int, unsigned short);
using FuncType_fcntl    = int(int, int, int);

#endif
