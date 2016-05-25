#ifndef KERNINT_ELFMODULELOADER64_H_
#define KERNINT_ELFMODULELOADER64_H_

#include "elfmoduleloader.h"

namespace kernint {

class ElfModuleLoader64 : public ElfModuleLoader {
public:
	ElfModuleLoader64(ElfFile64 *elffile,
	                  const std::string &name="",
	                  Kernel *kernel=nullptr);
	virtual ~ElfModuleLoader64();

protected:
};

} // namespace kernint

#endif
