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
m4_define([joy_minor_version], [4])
m4_define([joy_micro_version], [2])


m4_define([joy_version],[joy_major_version.joy_minor_version.joy_micro_version])
AC_PREREQ(2.69)

AC_INIT([joy],[joy_version],[https://github.com/cisco/joy/issues],[],[https://github.com/cisco/joy/])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_HEADERS([joy_config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PREFIX_DEFAULT(/usr/local/joy)

AM_INIT_AUTOMAKE([subdir-objects -Wall -Werror])
AC_USE_SYSTEM_EXTENSIONS
AM_MAINTAINER_MODE
AM_PROG_AR
#

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB
AC_FUNC_STRNLEN
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_TYPE_MODE_T
AC_TYPE_SSIZE_T
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AM_PROG_CC_C_O
AC_C_INLINE
AC_CHECK_TYPES([ptrdiff_t])
AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([socket])
AC_CHECK_FUNCS([strncasecmp])
AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([mkdir])
AC_CHECK_FUNCS([sqrt])
AC_CHECK_FUNCS([strcasecmp])
AC_CHECK_FUNCS([strchr])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([float.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([malloc.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([sys/timeb.h])
AC_CHECK_HEADERS([wchar.h])
AC_CHECK_HEADERS([ptrdiff.h])
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

tmp_am_cflags="-Werror -Wall -Wbad-function-cast -Wchar-subscripts -Wcomment -Wdeprecated-declarations -Wdisabled-optimization -Wdiv-by-zero -Wendif-labels -Wformat -Wformat-extra-args -Wformat-security -Wformat-y2k -Wimplicit -Wimplicit-function-declaration -Wimplicit-int -Wimport -Winline -Winvalid-pch -Wmain -Wmissing-braces -Wmissing-format-attribute -Wmissing-noreturn -Wmultichar -Wnested-externs -Wnonnull -Wparentheses -Wpointer-arith -Wreturn-type -Wsequence-point -Wsign-compare -Wstrict-aliasing -Wstrict-prototypes -Wswitch -Wswitch-default -Wswitch-enum -Wsystem-headers -Wtrigraphs -Wunknown-pragmas -Wunused -Wunused-function -Wunused-label -Wunused-parameter -Wunused-value -Wunused-variable -Wwrite-strings -Wno-pointer-sign -Wextra -fPIC -fPIE -D_FORTIFY_SOURCE=2 -O -D_GNU_SOURCE "



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



AC_CANONICAL_HOST
case "$host_os" in
  linux*)
        tmp_am_cflags+=" -Wunused-but-set-variable -Wcast-align -Wl,-z,noexecstack"
        AM_CONDITIONAL(BUILD_MAC, FALSE)
        AC_DEFINE([LINUX], [1], [Linux OS]);;
  darwin*)
        tmp_am_cflags+=" -Wno-expansion-to-defined -Wno-nullability-completeness"
        AM_CONDITIONAL(BUILD_MAC, TRUE)
        AC_DEFINE([DARWIN], [1], [MAC OS]);;
  *)
esac

AM_CFLAGS="$tmp_am_cflags"

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



AC_CHECK_LIB([dl], [dlopen], [AC_MSG_NOTICE("dl is installed")], 
                     AC_MSG_ERROR([dl not found. Please install it.]))
AC_CHECK_LIB([pthread], [pthread_equal], [AC_MSG_NOTICE("pthread is installed")], 
                     AC_MSG_ERROR([libpthread not found. Please install it.]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h])

AC_CHECK_HEADER([pcap.h],[found_pcap_header=yes; break;])
AS_IF([test "x$found_pcap_header" != "xyes"], [AC_MSG_ERROR([Unable to find pcap.h])])

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

AC_CHECK_LIB([crypto], [EVP_EncryptInit], [AC_MSG_NOTICE("openSSL is installed")],
             [AC_MSG_FAILURE([can't find openSSL libcrypto file])])

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
    AC_MSG_RESULT(no)
fi

#
# User wants af_packet
#
AC_MSG_CHECKING([enable af_packet])
AC_ARG_ENABLE(af_packet,
        [AS_HELP_STRING([--enable-af_packet],[enable the use of af_packet])],
        [enable_af_packet="yes"],
        [enable_af_packet="no"])  

if test "x$enable_af_packet" = "xyes"; then
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(BUILD_WITH_AF_PACKET, test "x$enable_af_packet" != "xno")



AC_MSG_CHECKING([SafeC Stubs])
SAFEC_STUB_DIR='$(abs_top_builddir)/safe_c_stub'
#AC_SUBST(SAFEC_STUB_DIR)

AC_ARG_WITH([safec-dir],
            [AS_HELP_STRING([--with-safec-dir=],
                [location of SAFEC install folder, This is an optional option. SafecStubs is the default])],
            [safecdir="$withval"],
            [safecdir="no"])

if test "x$safecdir" != "xno";then
   AC_SUBST([SAFEC_DIR], "$safecdir")
   AC_MSG_RESULT(no)
else
   AC_SUBST([SAFEC_DIR], "$SAFEC_STUB_DIR")
   AC_MSG_RESULT(yes)
fi
AM_CONDITIONAL(BUILD_WITH_SAFEC, test "x$safecdir" != "xno")
#AC_SUBST([SAFEC_DIR], "$safecdir")
 

AC_CONFIG_FILES([
                Makefile
                safe_c_stub/Makefile
                safe_c_stub/lib/Makefile
                lib/Makefile
                bin/Makefile])
   
AC_OUTPUT
