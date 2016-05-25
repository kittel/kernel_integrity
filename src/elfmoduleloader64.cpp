#include "elfmoduleloader64.h"

#include "helpers.h"

#include "exceptions.h"


namespace kernint {

ElfModuleLoader64::ElfModuleLoader64(ElfFile64 *elffile,
                                     const std::string &name,
                                     Kernel *kernel)
	:
	ElfModuleLoader(elffile, name, kernel) {}

ElfModuleLoader64::~ElfModuleLoader64() {}


} // namespace kernint
