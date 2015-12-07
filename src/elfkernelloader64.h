#ifndef ELFKERNELOADER64_H
#define ELFKERNELOADER64_H

#include "elfkernelloader.h"

class ElfKernelLoader64 : public ElfKernelLoader {
public:
	ElfKernelLoader64(ElfFile64 *elffile);
	virtual ~ElfKernelLoader64();

protected:
	void addSymbols();
};


#endif  /* ELFKERNELOADER64_H */
