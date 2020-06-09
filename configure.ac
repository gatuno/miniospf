AC_INIT([miniospf], [0.1.0], [], [miniospf])

AC_REVISION([Revision 1])

AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_SRCDIR([src/miniospf.c])

# For debian systems, /usr as default
AC_PREFIX_DEFAULT([/usr])

AM_PROG_AR
LT_INIT

# We need Gcc
AC_PROG_CC

# and automake
AM_INIT_AUTOMAKE([-Wall -Werror])

# Translate this program
AM_GNU_GETTEXT_VERSION([0.19.3])
AM_GNU_GETTEXT([external])

ALL_LINGUAS=""
AC_SUBST(ALL_LINGUAS)

AM_PROG_CC_C_O

# Revisar el host
AC_CANONICAL_HOST

case $host_os in
  *mingw32* ) MINGW32=yes;;
          * ) MINGW32=no;;
esac
case $host_os in
  *cygwin* ) CYGWIN=yes;;
         * ) CYGWIN=no;;
esac
case $host_os in
  *linux* ) LINUX=yes;;
        * ) LINUX=no;;
esac
case $host_os in
 *darwin* ) MACOSX=yes;;
       * ) MACOSX=no;;
esac

AM_CONDITIONAL(MINGW32, test x$MINGW32 = xyes)
AM_CONDITIONAL(LINUX, test x$LINUX = xyes)
AM_CONDITIONAL(MACOSX, test x$MACOSX = xyes)

LIBNL_VERSION=3.4.0

AC_MSG_CHECKING([if you have libnl installed on your system])
PKG_CHECK_EXISTS([libnl-3.0 >= $LIBNL_VERSION], [AC_MSG_RESULT([yes])], [AC_MSG_FAILURE([libnl not found in your system])])
PKG_CHECK_MODULES(LIBNL, [libnl-3.0 >= $LIBNL_VERSION], [], [])

AC_CONFIG_HEADERS([config.h])

AC_CONFIG_FILES([
                 Makefile
                 lib/Makefile
                 src/Makefile
                 src6/Makefile
                 po/Makefile.in
])
#                 data/Makefile

AC_OUTPUT
