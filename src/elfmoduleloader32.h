#ifndef ELFMODULELOADER32_H
#define ELFMODULELOADER32_H

#include "elfmoduleloader.h"

class ElfModuleLoader32 : public ElfModuleLoader{
	public:
		ElfModuleLoader32(ElfFile32* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader32();
	protected:
};

#endif  /* ELFMODULELOADER32_H */