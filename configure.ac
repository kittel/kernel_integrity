dnl Process this file with autoconf to produce a configure script.

AC_PREREQ([2.65])
AC_INIT([kernint], [0.1], [kittel@sec.in.tum.de])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([-Wall])

#Include CPPUnit
#AM_PATH_CPPUNIT(1.12.1)

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/Makefile.am])
AC_CONFIG_HEADERS([config.h])
LT_INIT

# Checks for compilers
# check for C++ preprocessor and compiler and the library compiler
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CXXCPP
# reset compiler flags to initial flags
# add std=c++14 flags
AX_CXX_COMPILE_STDCXX_14

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_LIBTOOL_DLOPEN

# use the C++ compiler for the following checks
AC_LANG([C++])


# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([string])
AC_CHECK_HEADERS([iostream])
AX_BOOST_BASE
AX_BOOST_FILESYSTEM

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.


if test $cross_compiling = no; then
  AM_MISSING_PROG(HELP2MAN, help2man)
else
  HELP2MAN=:
fi

######################################################################
# DOXYGEN SUPPORT
######################################################################

DX_INIT_DOXYGEN([$PACKAGE_NAME],[Doxyfile], [doc])
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(ON)
DX_PS_FEATURE(OFF)

######################################################################

AC_CONFIG_FILES(Makefile)
AC_CONFIG_FILES(src/Makefile)

##########################################################################
# debug compilation support
##########################################################################

AC_MSG_CHECKING([whether to build with debug information])
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
        [enable debug data generation (def=no)])],
    [debugit="$enableval"],
    [debugit=no])
AC_MSG_RESULT([$debugit])

if test x"$debugit" = x"yes"; then
    AC_DEFINE([DEBUG],[],[Debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -ggdb -O0"
    AM_LDFLAGS="$AM_LDFLAGS"
else
    AC_DEFINE([NDEBUG],[],[No-debug Mode])
    AM_CXXFLAGS="$AM_CXXFLAGS -O3"
fi

##########################################################################

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])


OLDLIBS=$LIBS

AC_CHECK_LIB([vmi], [vmi_init], [],
			 [AC_MSG_ERROR(["Error! You need to have libvmi around."])]
)
AC_CHECK_HEADERS([libvmi/libvmi.h], [],
				 [AC_MSG_ERROR(["Error! You need to have libvmi headers around."])]
)
AC_CHECK_LIB([elf], [elf_begin], [],
			 [AC_MSG_ERROR(["Error! You need to have libelf around."])]
)
AC_CHECK_LIB([dwarf], [dwarf_init], [],
			 [AC_MSG_ERROR(["Error! You need to have libdwarf around."])],
			 ["-lelf"]
)
AC_CHECK_HEADERS([libdwarf/libdwarf.h], [],
				 [AC_MSG_ERROR(["Error! You need to have libdwarf headers around."])]
)
AC_CHECK_LIB([capstone], [cs_open], [],
			 [AC_MSG_ERROR(["Error! You need to have libcapstone around."])]
)
AC_CHECK_HEADERS([capstone/capstone.h], [],
				 [AC_MSG_ERROR(["Error! You need to have libcapstone headers around."])]
)

LIBS=$OLDLIBS

# Checks for libraries.
OLD_CXXFLAGS=$CXXFLAGS
OLD_CPPFLAGS=$CPPFLAGS
CXXFLAGS="$CXXFLAGS $GLIB_CFLAGS"
CPPFLAGS="$CPPFLAGS $GLIB_CFLAGS"
AC_CHECK_HEADERS([libdwarfparser/libdwarfparser.h], [],
                 [AC_MSG_ERROR(["Error! You need to have libdwarfparser headers around."])]
)

AC_CHECK_HEADERS([libvmiwrapper/libvmiwrapper.h], [],
                 [AC_MSG_ERROR(["Error! You need to have libvmiwrapper headers around."])]
)
CXXFLAGS=$OLD_CXXFLAGS
CPPFLAGS=$OLD_CPPFLAGS


##########################################################################

# distribute additional compiler and linker flags
# --> set these variables instead of CXXFLAGS or LDFLAGS
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CXXFLAGS])
AC_SUBST([AM_LDFLAGS])
AC_SUBST([LIBS])

#AC_CONFIG_FILES(
#	[vmiids.sh:src/vmiids/vmiids.sh.in],
#	[chmod +x vmiids.sh])


AC_OUTPUT
