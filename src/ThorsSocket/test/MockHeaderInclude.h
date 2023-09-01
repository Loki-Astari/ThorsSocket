
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "OpenSSLMacroWrappers.h"

using OpenType = int(const char*, int, unsigned short);
using FctlType = int(int, int, int);

