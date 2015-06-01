AM_CXXFLAGS = -ggdb -Wall -Wextra -Werror -fpic -I $(top_builddir)/src -std=c++1y -I /usr/include

kernint_CXXFLAGS=$(AM_CXXFLAGS) $(GLIB_CFLAGS) $(LIBS) \
				 -I $(top_builddir)/../libdwarfparser/ \
				 -I $(top_builddir)/../libdwarf/
kernint_LDFLAGS=$(GLIB_LIBS) \
				-L$(top_builddir)/../libdwarfparser/libdwarfparser/ \
				-L$(top_builddir)/../libdwarfparser/libvmiwrapper/ \
				-ldwarfparser -ldwarf -lelf \
				-lvmiwrapper \
				-L$(top_builddir)/../libdwarf/libdwarf/ \
				-lboost_system -lboost_filesystem

bin_PROGRAMS=kernint

kernintdir = $(includedir)/kernint

kernint_HEADERS=kernint.h \
				kernelvalidator.h \
				kernel_headers.h \
				elffile.h \
				elffile32.h \
				elffile64.h \
				elfloader.h \
				kernelmanager.h \
				elfkernelloader.h \
				elfmoduleloader.h \
				elfkernelloader32.h \
				elfkernelloader64.h \
				elfmoduleloader32.h \
				elfmoduleloader64.h \
				exceptions.h

kernint_SOURCES=kernint.cpp \
				kernelvalidator.cpp \
				kernel_headers.cpp \
				elffile.cpp \
				elffile32.cpp \
				elffile64.cpp \
				elfloader.cpp \
				kernelmanager.cpp \
				elfkernelloader.cpp \
				elfmoduleloader.cpp \
				elfkernelloader32.cpp \
				elfkernelloader64.cpp \
				elfmoduleloader32.cpp \
				elfmoduleloader64.cpp \
				exceptions.cpp
