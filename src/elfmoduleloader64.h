#ifndef ELFMODULELOADER64_H
#define ELFMODULELOADER64_H

#include "elfmoduleloader.h"

class ElfModuleLoader64 : public ElfModuleLoader {
public:
	ElfModuleLoader64(ElfFile64 *elffile,
	                  const std::string &name="",
	                  Kernel *kernel=nullptr);
	virtual ~ElfModuleLoader64();

protected:
	void addSymbols();
};

#endif  /* ELFMODULELOADER64_H */
