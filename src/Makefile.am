AM_CXXFLAGS = -Wall -Wextra -Werror -fpic -I $(top_builddir)/src -std=c++1y -I /usr/include

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
				kernel_headers.h \
				elffile.h \
				elfloader.h \
				exceptions.h

kernint_SOURCES=kernint.cpp \
				kernel_headers.cpp \
				elffile.cpp \
				elfloader.cpp \
				exceptions.cpp
