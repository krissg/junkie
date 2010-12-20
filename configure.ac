#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.65])

# These git commands will disapear from the generated configure script
AC_INIT(junkie, m4_esyscmd([(git describe --tags || (git symbolic-ref HEAD | cut -d/ -f 3-)) | tr -d '\n']), github@securactive.net, , http://github.com/securactive/junkie)
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([src/config.h])
LT_INIT()

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB(ssl, SHA1)
AC_CHECK_LIB(pcap, pcap_activate)
AC_CHECK_LIB(guile, scm_with_guile)
AC_CHECK_LIB(pthread, pthread_mutex_init)
AC_CHECK_LIB(ltdl, lt_dlopen)

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h limits.h malloc.h netinet/in.h sys/param.h sys/socket.h sys/time.h syslog.h sys/prctl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([clock_gettime gettimeofday localtime_r memmove memset mkdir regcomp rmdir sqrt strcasecmp strchr strdup strerror strncasecmp strstr strtoull prctl])

AC_CONFIG_FILES([
	Makefile
	include/Makefile
	src/Makefile
	src/tools/Makefile
	src/proto/Makefile
	plugins/dumper/Makefile
	config/Makefile
	tests/Makefile
])
AC_OUTPUT
