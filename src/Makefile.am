AM_CXXFLAGS = -ggdb -Wall -Wextra -pedantic -Wcast-align -fpic -I $(top_builddir)/src -std=c++14 -I /usr/include -O3 -pg

kernint_CXXFLAGS=$(AM_CXXFLAGS) $(GLIB_CFLAGS) $(LIBS)
kernint_LDFLAGS=$(GLIB_LIBS) \
                -ldwarfparser -ldwarf -lelf \
                -lvmi -lvmiwrapper \
                -lboost_system -lboost_filesystem -lpthread

bin_PROGRAMS=kernint

kernintdir = $(includedir)/kernint

kernint_HEADERS=kernint.h \
                kernelvalidator.h \
                processvalidator.h \
                kernel_headers.h \
                elffile.h \
                elffile64.h \
                elfloader.h \
                kernel.h \
                elfkernelloader.h \
                elfmoduleloader.h \
                elfuserspaceloader.h \
                elfkernelloader64.h \
                elfmoduleloader64.h \
                elfuserspaceloader64.h \
                taskmanager.h \
                exceptions.h \
                paravirt_state.h \
                paravirt_patch.h \
                process.h \
                helpers.h

kernint_SOURCES=kernint.cpp \
                kernelvalidator.cpp \
                processvalidator.cpp \
                kernel_headers.cpp \
                elffile.cpp \
                elffile64.cpp \
                elfloader.cpp \
                kernel.cpp \
                elfkernelloader.cpp \
                elfmoduleloader.cpp \
                elfuserspaceloader.cpp \
                elfkernelloader64.cpp \
                elfmoduleloader64.cpp \
                elfuserspaceloader64.cpp \
                taskmanager.cpp \
                exceptions.cpp \
                paravirt_state.cpp \
                paravirt_patch.cpp \
                process.cpp \
                helpers.cpp
