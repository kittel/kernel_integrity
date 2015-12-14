#include "elfkernelloader64.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfKernelLoader64::ElfKernelLoader64(ElfFile64 *elffile)
	:
	ElfKernelLoader(elffile) {}

ElfKernelLoader64::~ElfKernelLoader64() {}
