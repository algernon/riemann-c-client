# -*- Autoconf -*-

AC_INIT([riemann-c-client], [1.10.4], [algernon@madhouse-project.org])
AM_INIT_AUTOMAKE([foreign subdir-objects dist-xz no-dist-gzip serial-tests])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_SRCDIR([lib/riemann/client.c])
AC_CONFIG_HEADERS([lib/riemann/platform.h])
AC_CONFIG_MACRO_DIR([m4])

# Before making a release, the LRC_LT_VERSION string should be modified.
# The string is of the form C:R:A.
# a) If binary compatibility has been broken (eg removed or changed interfaces)
#    change to C+1:0:0. DO NOT DO THIS! Use symbol versioning instead and
#    do b) instead.
# b) If interfaces have been changed or added, but binary compatibility has
#    been preserved, change to C+1:0:A+1
# c) If the interface is the same as the previous version, change to C:R+1:A
LRC_LT_VERSION=10:4:10
AC_SUBST(LRC_LT_VERSION)

AC_SUBST(MAJOR_VERSION, `echo $PACKAGE_VERSION | sed 's/\(.*\)\..*\..*/\1/g'`)
AC_SUBST(MINOR_VERSION, `echo $PACKAGE_VERSION | sed 's/.*\.\(.*\)\..*/\1/g'`)
AC_SUBST(PATCH_VERSION, [[`echo $PACKAGE_VERSION | sed 's/.*\..*\.\([0-9]*\).*/\1/g'`]])
AC_SUBST(NUMBER_VERSION, `printf "0x%02x%02x%02x" $MAJOR_VERSION $MINOR_VERSION $PATCH_VERSION`)

AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CXX

LT_INIT([shared])

AC_CHECK_PROG([HAS_PROTOC_C], [protoc-c], [yes])
if test x$HAS_PROTOC_C != x"yes"; then
   AC_MSG_ERROR([You need protoc-c installed and on your path to proceed. You can find it at http://code.google.com/p/protobuf-c/])
fi

AC_CHECK_HEADERS([arpa/inet.h netdb.h stdlib.h sys/socket.h])
AC_CHECK_FUNCS([memset socket strcasecmp strchr strdup strerror])
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T
AC_TYPE_INT64_T
AC_TYPE_SSIZE_T

# Check for pkg-config-enabled libraries
PKG_PROG_PKG_CONFIG

# Check for protobuf-c
PKG_CHECK_MODULES(PROTOBUF_C, libprotobuf-c,,
 [dnl No libprotobuf-c found with pkg-config.
  dnl Fall back to manually trying to find it.
  ac_save_LIBS=$LIBS
  ac_save_CFLAGS=$CFLAGS

  LIBS="$PROTOBUF_C_LIBS $LIBS"
  CFLAGS="$PROTOBUF_C_CFLAGS $CFLAGS"
  AC_CHECK_LIB(protobuf-c, protobuf_c_message_pack,
    [PROTOBUF_C_LIBS="${PROTOBUF_C_LIBS:--lprotobuf-c}"],
    [AC_MSG_ERROR([Can't link against protobuf-c lib, please set PROTOBUF_C_CFLAGS/PROTOBUF_C_LIBS before calling configure])])

  LIBS=$ac_save_LIBS
  CFLAGS=$ac_save_CFLAGS])

HAVE_CHECK=yes
PKG_CHECK_MODULES(CHECK, check,,[HAVE_CHECK="no"])
HAVE_JSON_C=yes
PKG_CHECK_MODULES(JSON_C, json-c >= 0.11,,[HAVE_JSON_C="no"])

HAVE_GNUTLS="auto"
AC_ARG_ENABLE([tls],
  AS_HELP_STRING([--disable-tls], [disable TLS support (default: auto)]))

case "${enable_tls}" in
     no)
        HAVE_GNUTLS="no"
        ;;
     yes)
        PKG_CHECK_MODULES(GNUTLS, gnutls >= 2.8)
        ;;
     *)
        PKG_CHECK_MODULES(GNUTLS, gnutls >= 2.8,, [HAVE_GNUTLS="no"])
        ;;
esac

# Check for linker version script support.
enable_value () {
   case "$1" in
        yes|y*)
                echo 1
                ;;
        *)
                echo 0
                ;;
   esac
}

ac_save_LDFLAGS=$LDFLAGS
AC_CACHE_CHECK(whether $LD supports symbol version scripts,
        ac_cv_prog_ld_version_script,
        [ac_cv_prog_ld_version_script=no
         echo "TEST { local: *; };" > conftest.ver
         LDFLAGS="$LDFLAGS -Wl,--version-script,conftest.ver"
         _AC_LINK_IFELSE([AC_LANG_PROGRAM()],
                [ac_cv_prog_ld_version_script=yes], [])
        ])
LDFLAGS=$ac_save_LDFLAGS
AM_CONDITIONAL([HAVE_VERSIONING], [test x$ac_cv_prog_ld_version_script = xyes])
AC_DEFINE_UNQUOTED(HAVE_VERSIONING, `enable_value ${ac_cv_prog_ld_version_script}`,
                   [Define to 1 if symbol versioning is enabled])

AM_CONDITIONAL([HAVE_JSON_C], [test x$HAVE_JSON_C != xno])
AM_CONDITIONAL([HAVE_CHECK], [test x$HAVE_CHECK != xno])

AC_DEFINE_UNQUOTED([HAVE_JSON_C],
  `if test x$HAVE_JSON_C != xno; then echo 1; else echo 0; fi`,
  [Define when json-c is available])
AC_DEFINE_UNQUOTED([HAVE_GNUTLS],
  `if test x$HAVE_GNUTLS != xno; then echo 1; else echo 0; fi`,
  [Define when GnuTLS is available])

AC_CONFIG_FILES([
        Makefile
        lib/riemann/riemann-client.h
        lib/riemann/riemann-client.pc
])
AC_OUTPUT
