AC_INIT([mimegrep], [0.2], [werner@suse.de])
AC_PREREQ([2.69])
AM_INIT_AUTOMAKE([-Wportability])
AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CPP
AC_PROG_GREP
date=`date -u -r ChangeLog +'%Y-%m-%d'`
AC_SUBST([date])dnl
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile mgrep.1])
AC_CHECK_HEADERS([ctype.h string.h ctype.h errno.h err.h getopt.h limits.h locale.h pipeline.h regex.h signal.h stdio.h stdlib.h string.h sys/types.h unistd.h])
AC_CHECK_FUNCS([regcomp regexec regerror regfree])
PKG_CHECK_MODULES([libpipeline], [libpipeline >= 1.4.1])
AC_OUTPUT
