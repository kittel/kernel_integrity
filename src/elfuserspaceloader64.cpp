#include "elfuserspaceloader64.h"

namespace kernint {

ElfUserspaceLoader64::ElfUserspaceLoader64(ElfFile64 *file,
                                       Kernel *kernel,
                                       const std::string &name)
	:
	ElfUserspaceLoader(file, kernel, name),
	bindLazy(true) {
}

ElfUserspaceLoader64::~ElfUserspaceLoader64() {
}

int ElfUserspaceLoader64::evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym> *map) {
	UNUSED(addr);
	UNUSED(map);
	std::cout << "TODO: eval lazy implementation" << std::endl;
	assert(0);
}

} // namespace kernint
