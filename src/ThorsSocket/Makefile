THORSANVIL_ROOT             = $(realpath ../../)
COVERAGE_REQUIRED			= 70

TARGET                      = ThorsSocket.slib
NAMESPACE					= ThorsAnvil::ThorsSocket

LDLIBS_EXTERN_BUILD			= crypto ThorSerialize
LDLIBS_MSYS_NT				= -lws2_32 -lwsock32
LDLIBS_MINGW64_NT			= -lws2_32 -lwsock32

UNITTEST_LDLIBS				+= $(LDLIBS_$(PLATFORM))
LDLIBS						+= $(LDLIBS_$(PLATFORM))

FILE_WARNING_FLAGS			+= -Wno-format -Wno-unused-variable

include $(THORSANVIL_ROOT)/build/tools/Makefile
