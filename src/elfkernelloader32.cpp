#include "elfkernelloader32.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfKernelLoader32::ElfKernelLoader32(ElfFile32* elffile)
	:
	ElfKernelLoader(elffile) {}

ElfKernelLoader32::~ElfKernelLoader32() {}
