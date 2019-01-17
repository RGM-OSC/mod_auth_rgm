#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(src/mod_auth_eon)
AC_CONFIG_AUX_DIR(autom4)
AC_CONFIG_SRCDIR([src/mod_auth_eon.c])
AM_INIT_AUTOMAKE(mod_auth_eon, 5.0)

# Set some argument variables.
AC_ARG_VAR(APACHE2_PREFIX, [Base path containing the Apache2 installation])
AC_ARG_VAR(APR0_PREFIX, [Base path containing the Apache2 Portable Runtime Library, series 0, installation])
AC_ARG_VAR(APR1_PREFIX, [Base path containing the Apache2 Portable Runtime Library, series 1, installation])
AC_ARG_VAR(MYSQL_PREFIX, [Base path containing the MySQL installation])
AC_ARG_VAR(APACHE2_INCLUDE, [Path to the Apache2 header file directory])
AC_ARG_VAR(APR0_INCLUDE, [Path to the Apache2 Portable Runtime Library, series 0, header file directory])
AC_ARG_VAR(APR1_INCLUDE, [Path to the Apache2 Portable Runtime Library, series 1, header file directory])
AC_ARG_VAR(MYSQL_INCLUDE, [Path to the MySQL header directory])
AC_ARG_VAR(MYSQLCLIENT_LIBPATH, [Path to the directory containing the MySQL client library])
AC_CONFIG_MACRO_DIR([m4])
if test -z "$APACHE2_PREFIX"; then
	APACHE2_PREFIX=/usr
fi
if test -z "$APR0_PREFIX"; then
	APR0_PREFIX=$APACHE2_PREFIX
fi
if test -z "$APR1_PREFIX"; then
	APR1_PREFIX=$APACHE2_PREFIX
fi
if test -z "$MYSQL_PREFIX"; then
	MYSQL_PREFIX=/usr
fi
if test -z "$APACHE2_INCLUDE"; then
	APACHE2_INCLUDE=$APACHE2_PREFIX/include
fi
if test -z "$APR0_INCLUDE"; then
	APR0_INCLUDE=$APR0_PREFIX/include
fi
if test -z "$APR1_INCLUDE"; then
	APR1_INCLUDE=$APR1_PREFIX/include
fi
if test -z "$MYSQL_INCLUDE"; then
	MYSQL_INCLUDE=$MYSQL_PREFIX/include
fi
if test -z "$MYSQLCLIENT_LIBPATH"; then
	MYSQLCLIENT_LIBPATH=$MYSQL_PREFIX/lib
	MYSQLCLIENT_LIBFLAGS=-L$MYSQLCLIENT_LIBPATH
fi
AC_ARG_ENABLE(debug,
	[  --enable-debug          turn on debug messages],
	[debug=yes])
if test "$debug" = "yes"; then
	AC_DEFINE(MAF_DEBUG, "1")
fi
AC_SUBST(APACHE2_INCLUDE)
AC_SUBST(APR_INCLUDE)
AC_SUBST(MYSQL_PREFIX)
AC_SUBST(MYSQL_INCLUDE)
AC_SUBST(MYSQLCLIENT_LIBFLAGS)
AC_SUBST(MYSQLCLIENT_LIB)

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL
AC_PATH_PROG(APXS, apxs2, "no")
if test "$APXS" = "no"; then
	if test -e $APACHE2_PREFIX/bin/apxs2; then
		APXS=$APACHE2_PREFIX/bin/apxs2
		AC_MSG_RESULT([Apache2 'apxs2' found.])
	else
		AC_MSG_RESULT([Apache2 'apxs2' cannot be found. Checking for
			Apache2 'apxs'.])
	fi
fi
if test "$APXS" = "no"; then
	AC_PATH_PROG(APXS, apxs, "no")
	if test "$APXS" = "no"; then
		if test -e $APACHE2_PREFIX/bin/apxs; then
			APXS=$APACHE2_PREFIX/bin/apxs
			AC_MSG_RESULT([Apache2 'apxs' found.])
		else
			AC_MSG_WARN([Apache2 'apxs' cannot be found. Check
				your binary paths and/or correct APACHE2_PREFIX. This is
				needed to build the .so file for installation.])
		fi
	fi
fi

# Checks for libraries.
if test -e $MYSQLCLIENT_LIBPATH/mysql; then
	MYSQLCLIENT_LIBFLAGS="$MYSQLCLIENT_LIBFLAGS -L$MYSQLCLIENT_LIBPATH/mysql"
fi
LDFLAGS="$LDFLAGS $MYSQLCLIENT_LIBFLAGS"

AC_CHECK_LIB(z, compress,, AC_MSG_WARN([
	ZLib could not be found. This may result in an unstable
	module.]))
AC_CHECK_LIB(pthread, pthread_key_create, pthread="yes", pthread="no")
if test "$pthread" = "yes"; then
  MYSQLCLIENT_LIBFLAGS="$MYSQLCLIENT_LIBFLAGS -lpthread"
  LDFLAGS="$LDFLAGS -lpthread"
  MYSQLCLIENT_LIB=mysqlclient_r
  AC_CHECK_LIB(mysqlclient_r, mysql_init, threadsafe_mysql="yes", threadsafe_mysql="no")
fi
if test "$threadsafe_mysql" != "yes"; then
	MYSQLCLIENT_LIB=mysqlclient
  AC_MSG_WARN([
      Cannot link with thread-safe MySQL client library (libmysqlclient_r)])
  AC_CHECK_LIB($MYSQLCLIENT_LIB, mysql_init,, AC_MSG_ERROR([
        The MySQL client library could not be found. Please check the
        MySQL installation and correct MYSQL_PREFIX.]))
fi
AC_CHECK_LIB($MYSQLCLIENT_LIB, mysql_ssl_set, AC_DEFINE(MAF_MYSQL_SSL, "1"), AC_MSG_WARN([
  The MySQL client library does not support SSL. Disabling
  SSL support for MySQL.]))

# Check for key header files (manually)
if test ! -e $APACHE2_INCLUDE/httpd.h; then
	APACHE2_INCLUDE=$APACHE2_PREFIX/include/apache2
	if test ! -e $APACHE2_INCLUDE/httpd.h; then
		AC_MSG_ERROR([
			The Apache2 header files could not be found.
			Please correct APACHE2_PREFIX or APACHE2_INCLUDE.])
	fi
fi
if test ! -e $APR1_INCLUDE/apr_hooks.h; then
	APR1_INCLUDE=$APR1_PREFIX/include/apr-1
	if test ! -e $APR1_INCLUDE/apr_hooks.h; then
		AC_MSG_WARN([
			The Apache2 Portable Runtime Library, series 1, header files could not be found.
			Please correct APR1_PREFIX or APR1_INCLUDE if APR-1.x is installed.])
		if test ! -e $APR0_INCLUDE/apr_hooks.h; then
			APR0_INCLUDE=$APR0_PREFIX/include/apr-0
			if test ! -e $APR0_INCLUDE/apr_hooks.h; then
				AC_MSG_WARN([
					The Apache2 Portable Runtime Library, series 0, header files could not be found.
					Please correct APR0_PREFIX or APR0_INCLUDE if APR-0.x is installed.])
				AC_MSG_ERROR([
					The Apache2 Portable Runtime Library header files could not be found.
					Please check your APR installation.])
			fi
		fi
	fi
fi
if test -e $APR1_INCLUDE/apr_hooks.h;then
	APR_INCLUDE=$APR1_INCLUDE
elif test -e $APR0_INCLUDE/apr_hooks.h;then
	APR_INCLUDE=$APR0_INCLUDE
fi
if test ! -e $MYSQL_INCLUDE/mysql.h; then
	MYSQL_INCLUDE=$MYSQL_PREFIX/include/mysql
	if test ! -e $MYSQL_INCLUDE/mysql.h; then
		AC_MSG_ERROR([
			The MySQL header files could not be found. Please
			correct MYSQL_PREFIX or MYSQL_INCLUDE.])
	fi
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST

# Checks for library functions.
AC_CHECK_FUNCS([strchr strrchr strstr strtol],, AC_MSG_ERROR([Missing a standard string function.]))

# Finally, output the results
AC_CONFIG_FILES([Makefile
                 src/Makefile])
#AC_CONFIG_COMMANDS([time-stamp], [$DATE > stamp-h.in])
AC_OUTPUT
