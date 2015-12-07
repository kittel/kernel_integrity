#ifndef ELFMODULELOADER64_H
#define ELFMODULELOADER64_H

#include "elfmoduleloader.h"

class ElfModuleLoader64 : public ElfModuleLoader {
public:
	ElfModuleLoader64(ElfFile64 *elffile,
	                  const std::string &name="",
	                  Kernel *kernel=nullptr);
	virtual ~ElfModuleLoader64();

	void applyRelocationsOnSection(uint32_t relSectionID);

protected:
	uint64_t relocateShnUndef(const std::string &symbolName);
	void addSymbols();
};

#endif  /* ELFMODULELOADER64_H */
