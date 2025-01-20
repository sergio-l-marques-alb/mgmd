#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

#AC_PREREQ([2.68])

define([PTIN_MGMD_SVN_RELEASE], esyscmd([sh -c "svnversion -n"]))dnl
define([PTIN_MGMD_SVN_VERSION], 1.3.0)dnl
define([PTIN_MGMD_SVN_PACKAGE], PTIN_MGMD_SVN_VERSION.PTIN_MGMD_SVN_RELEASE)dnl
AC_INIT([Multicast Group Membership Discovery], [PTIN_MGMD_SVN_PACKAGE], [hdcare@ptinovacao.pt], [mgmd])
AC_CONFIG_HEADERS([config.h])
AC_COPYRIGHT([Copyright 2014 PT Inovacao, SA.  All rights reserved.  Use is subject to license terms])
AM_INIT_AUTOMAKE([-Wall])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])
m4_pattern_allow([AM_PROG_AR], [AM_PROG_AR])  #AM_PROG_AR
# Checks for programs.
AC_PROG_LIBTOOL
AC_PROG_CC
AC_PROG_MAKE_SET
AM_PROG_CC_C_O
# Checks for libraries.
# FIXME: Replace `main' with a function in `-lpthread':
AC_CHECK_LIB([pthread], [main])
# FIXME: Replace `main' with a function in `-lrt':
AC_CHECK_LIB([rt], [main])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
#AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero gettimeofday localtime_r memset socket strerror strtoul])

MGMD_LIBS="-lpthread -lrt"
AC_SUBST(MGMD_LIBS)
#LIBS="${LIBS} ${MGMD_LIBS}"

#MGMD_CFLAGS="-Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-strict-aliasing -Wstack-protector -fstack-check -fstack-protector-all -g -ggdb"
MGMD_CFLAGS="-Wall -Wextra -Werror -Wno-missing-field-initializers -Wno-strict-aliasing -g -Os"
AC_SUBST(MGMD_CFLAGS)
#CFLAGS="${CFLAGS} ${MGMD_CFLAGS}"

RFS_PATH=$DESTDIR
AC_SUBST(RFS_PATH)

# 1 - Para utilizar a liblogger             : ./configure
# 2 - Para utilizar dinamicamente um logger : ./configure --without-logger
# 1 - Para utilizar o logger interno do mgmd: ./configure --without-logger --enable-int-logger

MGMD_LOGGER=
LIBLOGGER=
AC_ARG_WITH([liblogger],[AS_HELP_STRING([--without-liblogger],[disable support for logger])],[],[with_liblogger=yes])
AC_ARG_ENABLE([int_logger], AS_HELP_STRING([--enable-int-logger], [Creates MGMD with an internal logger]))
AS_IF([test "x$enable_int_logger" = "xyes"], [int_logger=yes], [int_logger=no])
AS_IF([test "x$with_liblogger" != xno], 
   [LIBS="$LIBS -lz"; MGMD_LOGGER="MGMD_LOGGER_LIBLOGGER"; AC_CHECK_LIB([logger], [main], [AC_SUBST([LIBLOGGER], ["-llogger"]) AC_DEFINE([HAVE_LIBLOGGER], [1],[Define if you have liblogger])], [AC_MSG_FAILURE( [liblogger test failed (--without-liblogger to disable)])], [])],
   AS_IF([test "x$int_logger" = "xno"], [MGMD_LOGGER="MGMD_LOGGER_DYNAMIC"], [MGMD_LOGGER="MGMD_LOGGER_INTERNAL"])
)
AC_SUBST(MGMD_LOGGER)

AC_ARG_ENABLE([binary], AS_HELP_STRING([--enable-binary], [Creates a MGMD standalone binary]))
AS_IF([test "x$enable_binary" = "xyes"], [binary=yes], [binary=no])
AS_IF([test "x$binary" = "xyes"], [AC_DEFINE(_COMPILE_AS_BINARY_, [], ["Creates a MGMD standalone binary"])])
AS_IF([test "x$binary" = "xyes"], [MGMD_CFLAGS+=" -D_COMPILE_AS_BINARY_"])
AM_CONDITIONAL([ENABLE_PTIN_BINARY], [test "x$binary" = "xyes"])

AC_ARG_VAR([PTIN_MGMD_PLATFORM_CTRL_TIMEOUT],[Number of seconds to wait for MGMD to answer a CTRL event])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE],[Maximum size for the MGMD queue (in bytes)])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_STACK_SIZE],[Stack size to be used in mgmd and timers threads])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_CHANNELS],[Maximum number of channels])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_WHITELIST],[Maximum number of white-list entries])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_CLIENTS],[Maximum number of clients])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_PORTS],[Maximum number of ports])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_PORT_ID],[Maximum Port Identifier])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_SERVICES], [Maximum number of services])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_SERVICE_ID], [Maximum Service Identifier])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE], [Maximum frame size])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT], [Admission Control Support])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID], [Root Port Is On Max Port Id])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_SVN_VERSION], [SVN Version])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_SVN_RELEASE], [SVN Release])
AC_ARG_VAR([PTIN_MGMD_PLATFORM_SVN_PACKAGE], [SVN Package])

if test -z $PTIN_MGMD_PLATFORM_CTRL_TIMEOUT;then PTIN_MGMD_PLATFORM_CTRL_TIMEOUT=10;fi
if test -z $PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE;then PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE=1000000;fi
if test -z $PTIN_MGMD_PLATFORM_STACK_SIZE;then PTIN_MGMD_PLATFORM_STACK_SIZE=10*32*1024;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_CHANNELS;then PTIN_MGMD_PLATFORM_MAX_CHANNELS=4096;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_WHITELIST;then PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_CLIENTS;then PTIN_MGMD_PLATFORM_MAX_CLIENTS=128;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_PORTS;then PTIN_MGMD_PLATFORM_MAX_PORTS=48;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_PORT_ID;then PTIN_MGMD_PLATFORM_MAX_PORT_ID=$PTIN_MGMD_PLATFORM_MAX_PORTS;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_SERVICES;then PTIN_MGMD_PLATFORM_MAX_SERVICES=40;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_SERVICE_ID;then PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=255;fi
if test -z $PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE; then PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE=1500;fi
if test -z $PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT; then PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=0;fi
if test -z $PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID; then PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=0;fi
if test -z $PTIN_MGMD_PLATFORM_SVN_VERSION; then PTIN_MGMD_PLATFORM_SVN_VERSION=PTIN_MGMD_SVN_VERSION;fi
if test -z $PTIN_MGMD_PLATFORM_SVN_RELEASE; then PTIN_MGMD_PLATFORM_SVN_RELEASE=PTIN_MGMD_SVN_RELEASE;fi
if test -z $PTIN_MGMD_PLATFORM_SVN_PACKAGE; then PTIN_MGMD_PLATFORM_SVN_PACKAGE=PTIN_MGMD_SVN_PACKAGE;fi

AC_SUBST(PTIN_MGMD_PLATFORM_CTRL_TIMEOUT)
AC_SUBST(PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE)
AC_SUBST(PTIN_MGMD_PLATFORM_STACK_SIZE)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_CHANNELS)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_WHITELIST)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_CLIENTS)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_PORTS)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_PORT_ID)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_SERVICES)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_SERVICE_ID)
AC_SUBST(PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE)
AC_SUBST(PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT)
AC_SUBST(PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID)
AC_SUBST(PTIN_MGMD_PLATFORM_SVN_VERSION)
AC_SUBST(PTIN_MGMD_PLATFORM_SVN_RELEASE)
AC_SUBST(PTIN_MGMD_PLATFORM_SVN_PACKAGE)
AS_IF([test $PTIN_MGMD_PLATFORM_MAX_WHITELIST -lt $PTIN_MGMD_PLATFORM_MAX_CHANNELS], AC_MSG_ERROR([The white-list must support at least max_channels entries]))


#
# unless explicitly set, drop previx from sysconfdir
# and localstatedir
#
if test "$sysconfdir" = '${prefix}/etc' ; then
        if test "$prefix" = 'NONE' ; then
                sysconfdir="/etc"
        else
                sysconfdir="$prefix"/etc
fi      
fi
AC_SUBST([sysconfdir])

if test "$localstatedir" = '${prefix}/var' ; then
        if test "$prefix" = 'NONE' ; then
                localstatedir="/var"
        else
                localstatedir="$prefix"/var
        fi
fi
AC_SUBST([localstatedir])


AC_CONFIG_FILES([Makefile 
                 src/Makefile
                 src/ptin_mgmd_defs.h
                 mgmd.pc])
AC_OUTPUT
echo "
mgmd configuration
--------------------
version				                 : ${version}
host operationg system		                 : ${host_os}
target				                 : ${target}
compiler			                 : ${CC}
compiler flags			                 : ${CFLAGS}
linker flags			                 : ${LDFLAGS} ${LIBS}
prefix				                 : ${prefix}
exec_prefix			                 : ${exec_prefix}
libdir				                 : ${libdir}
bindir				                 : ${bindir}
sbindir				                 : ${sbindir}
PTIN_MGMD_PLATFORM_CTRL_TIMEOUT	                 : ${PTIN_MGMD_PLATFORM_CTRL_TIMEOUT}
PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE                 : ${PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE}
PTIN_MGMD_PLATFORM_STACK_SIZE	                 : ${PTIN_MGMD_PLATFORM_STACK_SIZE}
PTIN_MGMD_PLATFORM_MAX_CHANNELS	                 : ${PTIN_MGMD_PLATFORM_MAX_CHANNELS}
PTIN_MGMD_PLATFORM_MAX_WHITELIST                 : ${PTIN_MGMD_PLATFORM_MAX_WHITELIST}
PTIN_MGMD_PLATFORM_MAX_CLIENTS	                 : ${PTIN_MGMD_PLATFORM_MAX_CLIENTS}
PTIN_MGMD_PLATFORM_MAX_PORTS	                 : ${PTIN_MGMD_PLATFORM_MAX_PORTS}
PTIN_MGMD_PLATFORM_MAX_PORT_ID	                 : ${PTIN_MGMD_PLATFORM_MAX_PORT_ID}
PTIN_MGMD_PLATFORM_MAX_SERVICES	                 : ${PTIN_MGMD_PLATFORM_MAX_SERVICES}
PTIN_MGMD_PLATFORM_MAX_SERVICE_ID                : ${PTIN_MGMD_PLATFORM_MAX_SERVICE_ID}
PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE                : ${PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE}
PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT     : ${PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT}
PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID   : ${PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID}
PTIN_MGMD_PLATFORM_SVN_VERSION                   : ${PTIN_MGMD_PLATFORM_SVN_VERSION}
PTIN_MGMD_PLATFORM_SVN_RELEASE                   : ${PTIN_MGMD_PLATFORM_SVN_RELEASE}
PTIN_MGMD_PLATFORM_SVN_PACKAGE                   : ${PTIN_MGMD_PLATFORM_SVN_PACKAGE}
" > /dev/stderr

