AM_CXXFLAGS += -Wall -Wextra -pedantic -Wcast-align -fpic $(GLIB_CFLAGS) $(LIBS) # -fsanitize=address

kernint_LDFLAGS=$(GLIB_LIBS) \
                -ldwarfparser -ldwarf -lelf -ldl \
                -lvmi -lvmiwrapper \
                -lboost_system -lboost_filesystem \
                -lpthread \
                -lcapstone

bin_PROGRAMS=kernint

kernintdir = $(includedir)/kernint

kernint_HEADERS=kernint.h \
                kernelvalidator.h \
                processvalidator.h \
                kernel_headers.h \
                elffile.h \
                elffile64.h \
                elfloader.h \
                error.h \
                kernel.h \
                elfkernelspaceloader.h \
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
                error.cpp \
                kernel.cpp \
                elfkernelspaceloader.cpp \
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
