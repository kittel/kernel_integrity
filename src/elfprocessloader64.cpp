#include "elfprocessloader64.h"

ElfProcessLoader64::ElfProcessLoader64(ElfFile64 *file,
                                       Kernel *kernel,
                                       const std::string &name)
	:
	ElfProcessLoader(file, kernel, name),
	bindLazy(true) {
}

ElfProcessLoader64::~ElfProcessLoader64() {
}

int ElfProcessLoader64::evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym> *map) {
	std::cout << "TODO: eval lazy implementation" << std::endl;
	assert(0);
}
