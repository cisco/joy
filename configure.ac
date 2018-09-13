#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# When to bump versions.
# Major - Bumped if an API or ABI changes, Build changes etc. 
# Minor - Bumped for every release of software
# Micro - Bumped for patch releases only
# age - Represents how many revisions back of the Major/Current this library
#       supports. Each library client, Mgmt, common can be ABI compatible
#       depending on the change in the library.
#       
#       Once a number gets incremented all numbers to the left get reset to zero.
# Shared objects are named library.so.Major.age.Minor by autotools
#
m4_define([joy_major_version], [4])
m4_define([joy_minor_version], [0])
m4_define([joy_micro_version], [0])


m4_define([joy_version],[joy_major_version.joy_minor_version.joy_micro_version])
AC_PREREQ(2.63)

AC_INIT([joy],[joy_version],[TBD@cisco.com])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([joy_config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT(/usr/local/joy)

AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror])
AC_USE_SYSTEM_EXTENSIONS
AM_MAINTAINER_MODE
#

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_RANLIB
######################## PKG Versioning #######################
PKG_VERSION_NUMBER="joy_major_version:joy_minor_version:joy_micro_version"
AC_SUBST(PKG_VERSION_NUMBER)
AC_DEFINE(JOY_MAJOR_VERSION, joy_major_version, Package Major Version)
AC_DEFINE(JOY_MINOR_VERSION, joy_minor_version, Package Minor Version)
AC_DEFINE(JOY_MICRO_VERSION, joy_micro_version, Package Micro Version)

######################## Library Versioning ####################
#
# Create the AGE version for current:revision:age
# For each shared library
#
m4_define([joy_age], [0])              #joy.so age for version
JOY_LIBRARY_VERSION="joy_major_version:joy_minor_version:joy_age"
AC_SUBST(JOY_LIBRARY_VERSION)

LT_INIT

tmp_am_cflags="-Werror -Wall -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O"
tmp_am_cflags_no_cast_qual="-Werror -Wall -Wbad-function-cast -Wcast-align -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wunused-but-set-variable -Wwrite-strings -Wno-pointer-sign -Wextra -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O"

#tmp_am_cflags="-Werror -Wall -Wbad-function-cast -Wcast-align -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wshadow -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wunused-but-set-variable -Wwrite-strings -Wno-pointer-sign -Wextra -Wcast-qual -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O"

#
# Disabling cast-qual Support
#
AC_MSG_CHECKING([disable cast-qual Usage])
AC_ARG_ENABLE(cast-qual,
        [AS_HELP_STRING([--disable-cast-qual],[disable the use of cast-qual option])],
        [disable_cast_qual="yes"],
        [disable_cast_qual="no"])  

if test "x$disable_cast_qual" = "xyes"; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no);
fi


AM_CFLAGS="$tmp_am_cflags"

AC_CANONICAL_HOST
case "$host_os" in
  linux*)
        AC_DEFINE([LINUX], [1], [Linux OS]);;
  darwin*)
        AC_DEFINE([DARWIN], [1], [MAC OS]);;
  *)
esac

#
# Here if -disable-cast-qual was selected we would need to turn off
# cast qual. yes means it should be off. 
# else they don't want it and we turn if on assuming the distro allows it
#if test "x$disable_cast_qual" = "xyes"; then 
#   AM_CFLAGS="$tmp_am_cflags_no_cast_qual"
#else
   # Check if stdlib-bsearch.h is installed on the distro.
   # Implementation of bsearch from stdlib-bsearch.h causes build failure
   # with -Wcast-qual flags enabled. 
#   if test "x$cross_compiling" = "xno"; then
#      AC_CHECK_FILES(
#        /usr/include/i386-linux-gnu/bits/stdlib-bsearch.h  
#        /usr/include/x86_64-linux-gnu/bits/stdlib-bsearch.h,
#        [AM_CFLAGS="$tmp_am_cflags_no_cast_qual"],
#        )
#   fi
#fi


AM_CFLAGS_LITE="-Werror -Wall -fPIC"

AC_SUBST(AM_CFLAGS)
AC_SUBST(AM_CFLAGS_LITE)



AC_CHECK_LIB([dl], [dlopen])

AC_CHECK_LIB([pthread], [pthread_equal])


# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
#AC_FUNC_MALLOC
#AC_FUNC_STRNLEN
AC_CHECK_FUNCS([gettimeofday memsetstrcasecmp strdup strerror strndup strstr strtol strtoul calloc chmod rename remove])


#
# A user may have installed openssl in a location other than standard
# if so let them tell us where
#
AC_ARG_WITH([ssl-dir],
            [AS_HELP_STRING([--with-ssl-dir=],
                [location of openSSL install folder, This is optional#])],
            [ssldir="$withval"],
            [ssldir="/usr"])


if test "x$ssldir" != "x/usr"; then
   LDFLAGS="$LDFLAGS -L$ssldir/lib" 
   AC_SUBST([SSL_CFLAGS], "$ssldir/include")
   AC_SUBST([SSL_LDFLAGS], "-L$ssldir/lib")
fi

AC_CHECK_LIB([crypto], [EVP_EncryptInit], [],
             [AC_MSG_FAILURE([can't find openSSL libcrypto file])])

##
# Libcurl installation directory path
# to override defaults
##
AC_ARG_WITH([libcurl-dir],
    [AS_HELP_STRING([--with-libcurl-dir],
    [enable support for joy using libcurl])],
    [libcurldir="$withval"],
    [libcurldir="no"])

if test "x$libcurldir" != "xno"; then
   LDFLAGS="$LDFLAGS -L$libcurldir/lib" 
   AC_SUBST([CURL_CFLAGS], "$libcurldir/include")
   AC_SUBST([CURL_LDFLAGS], "-L$libcurldir/lib")

   AC_CHECK_LIB([curl], [curl_easy_install], [],
             [AC_MSG_FAILURE([--with-libcurl-dir was given, but test for libcurl failed])])
fi

AC_DEFINE([COMPRESSED_OUTPUT], [0], [Compression is disabled])
AC_MSG_CHECKING([enable bzip2])
AC_ARG_ENABLE(bzip2,
        [AS_HELP_STRING([--enable-bzip2],[enable the use of bzip2])],
        [enable_bzip2="yes"],
        [enable_bzip2="no"])  

#
# User want bzip2
#
if test "x$enable_bzip2" = "xyes"; then
    LDFLAGS="$LDFLAGS -lbz2"
    AC_MSG_RESULT(yes)
    AC_DEFINE([USE_BZIP2], [], [BZIP2 is enabled])
    AC_DEFINE([COMPRESSED_OUTPUT], [1], [Compression is enabled])
    AC_CHECK_HEADERS([bzlib.h],[ ],[AC_MSG_FAILURE([can't find bzlib.h])])
else
    AC_MSG_RESULT(no);
fi

#
# User wants gzip
#
AC_MSG_CHECKING([enable gzip])
AC_ARG_ENABLE(gzip,
        [AS_HELP_STRING([--enable-gzip],[enable the use of gzip])],
        [enable_gzip="yes"],
        [enable_gzip="no"])  

if test "x$enable_gzip" = "xyes"; then
    LDFLAGS="$LDFLAGS -lz"
    AC_MSG_RESULT(yes)
    AC_DEFINE([USE_GZIP], [], [GZIP is enabled])
    AC_DEFINE([COMPRESSED_OUTPUT], [1], [Compression is enabled])
    AC_CHECK_HEADERS([zlib.h])
    AC_CHECK_HEADERS([zlib.h],[ ],[AC_MSG_FAILURE([can't find zlib.h])])
else
    AC_MSG_RESULT(no);
fi




SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
AC_SUBST(SAFEC_STUB_DIR)

AC_ARG_WITH([safec-dir],
            [AS_HELP_STRING([--with-safec-dir=],
                [location of SAFEC install folder, This is an optional option. --disable-safec can be used to override])],
            [safecdir="$withval"],
            [safecdir="no"])

#AC_ARG_WITH([cunit-dir],
#            [AS_HELP_STRING([--with-cunit-dir=],
#                [location of cunit install folder for testing)],
#            [cunitdir="$withval"],
#            [cunitdir="/usr/local"])

#AC_SUBST([CUNIT_CFLAGS], "$cunitdir/include")

#
# Disabling SAFEC Support
#
#AC_MSG_CHECKING([disable SAFEC Usage])
#AC_ARG_ENABLE(safec,
#        [AS_HELP_STRING([--disable-safec],[disable SAFEC use: **WARNING** this #is not recommended])],
#        [disable_safec="yes"],
#        [disable_safec="no"])  

# If user didn't set safecdir and we are not disabling safec
# we notify the user.
#if test "x$disable_safec" = "xyes"; then
#    safecdir="$SAFEC_STUB_DIR" 
#    AC_MSG_RESULT(yes)
#else
#    AC_MSG_RESULT(no);
#fi

AC_SUBST([SAFEC_DIR], "$safecdir")
 

AC_CONFIG_FILES([
                Makefile
                safe_c_stub/Makefile
                safe_c_stub/lib/Makefile
                lib/Makefile
                bin/Makefile])
   
AC_OUTPUT
