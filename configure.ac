AC_INIT([ThorsSocket], [3.0], [Loki.Astari+ThorsSocket@gmail.com])
AC_PREREQ([2.65])

AC_CONFIG_MACRO_DIR([build/autotools/m4])
AC_CONFIG_AUX_DIR([build/autotools/build])

AX_THOR_FUNC_INIT_BUILD([ThorsSocket], [17], [src/ThorsSocket/Socket.cpp])

AX_THOR_CHECK_USE_CRYPTO
AX_THOR_CHECK_USE_THORS_SERIALIZE

LT_INIT

AX_THOR_FUNC_TERM_BUILD([SOCKET], [src/ThorsSocket/ThorsSocketConfig.h:config.h.in])

AC_OUTPUT
