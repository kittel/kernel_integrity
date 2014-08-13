AM_CXXFLAGS = -Wall -Wextra -Werror -fpic -I $(top_builddir)/src -std=c++1y

kernint_CXXFLAGS=$(AM_CXXFLAGS) $(GLIB_CFLAGS) $(LIBS) \
				 -I /home/kittel/projekte/code/libdwarfparser/ \
				 -I /home/kittel/projekte/code/libdwarf/
kernint_LDFLAGS=$(GLIB_LIBS) \
				-L/home/kittel/projekte/code/libdwarfparser/libdwarfparser/ \
				-L/home/kittel/projekte/code/libdwarfparser/libvmiwrapper/ \
				-ldwarfparser -ldwarf -lelf \
				-lvmiwrapper \
				-L/home/kittel/projekte/code/libdwarf/libdwarf/

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
