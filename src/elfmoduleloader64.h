#ifndef ELFMODULELOADER64_H
#define ELFMODULELOADER64_H

#include "elfmoduleloader.h"

class ElfModuleLoader64 : public ElfModuleLoader{
	public:
		ElfModuleLoader64(ElfFile64* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader64();

		void applyRelocationsOnSection(uint32_t relSectionID);
	protected:
		uint64_t relocateShnUndef(std::string symbolName);
		void addSymbols();
};

#endif  /* ELFMODULELOADER64_H */