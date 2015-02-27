#ifndef ELFKERNELOADER32_H
#define ELFKERNELOADER32_H

#include "elfkernelloader.h"

class ElfKernelLoader32 : public ElfKernelLoader{
	public:
		ElfKernelLoader32(ElfFile32* elffile);
		virtual ~ElfKernelLoader32();
	protected:
};

#endif  /* ELFKERNELOADER32_H */