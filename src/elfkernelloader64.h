#ifndef KERNINT_ELFKERNELOADER64_H_
#define KERNINT_ELFKERNELOADER64_H_

#include "elfkernelloader.h"

namespace kernint {

class ElfKernelLoader64 : public ElfKernelLoader {
public:
	ElfKernelLoader64(ElfFile64 *elffile);
	virtual ~ElfKernelLoader64();

protected:
};


} // namespace kernint

#endif
