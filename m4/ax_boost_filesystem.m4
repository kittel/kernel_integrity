AC_DEFUN([AX_BOOST_FILESYSTEM],
[AC_REQUIRE([AC_CXX_NAMESPACES])dnl
AC_CACHE_CHECK(whether the Boost::Filesystem library is available,
ax_cv_boost_filesystem,
[AC_LANG_SAVE
 AC_LANG_CPLUSPLUS
 AC_COMPILE_IFELSE(AC_LANG_PROGRAM([[#include <boost/filesystem/path.hpp>]],
                                   [[using namespace boost::filesystem;
                                   path my_path( "foo/bar/data.txt" );
                                   return 0;]]),
                   ax_cv_boost_filesystem=yes, ax_cv_boost_filesystem=no)
 AC_LANG_RESTORE
])
if test "$ax_cv_filesystem" = yes; then
  AC_DEFINE(HAVE_BOOST_FILE,,[define if the Boost::FILESYSTEM library is available])
  dnl Now determine the appropriate file names
  AC_ARG_WITH([boost-filesystem],AS_HELP_STRING([--with-boost-filesystem],
  [specify the boost filesystem library or suffix to use]),
  [if test "x$with_boost_filesystem" != "xno"; then
    ax_filesystem_lib=$with_boost_filesystem
    ax_boost_filesystem_lib=boost_filesystem-$with_boost_filesystem
  fi])
  for ax_lib in $ax_filesystem_lib $ax_boost_filesystem_lib boost_filesystem; do
    AC_CHECK_LIB($ax_lib, main, [BOOST_FILESYSTEM_LIB=$ax_lib break])
  done
  AC_SUBST(BOOST_FILESYSTEM_LIB)
fi
])dnl
