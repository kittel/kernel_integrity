#ifndef ELFUSERSPACELOADER64_H
#define ELFUSERSPACELOADER64_H

#include <algorithm>
#include <vector>
#include <unordered_map>
#include <elf.h>

#include "elfuserspaceloader.h"
#include "helpers.h"

#ifndef ASLROFFTYPE_M
#define ASLROFFTYPE_M

#define ASLR_BRK    1
#define ASLR_STACK  2
#define ASLR_VDSO   3

#endif //ASLROFFTYPE_M



/**
 * This class is a derivated ElfUserspaceLoader for use with 64-Bit Systems.
 * It holds a process image for validation, which is derived from the original
 * ELF by retracing the building process in the target system.
 */
class ElfUserspaceLoader64 : public ElfUserspaceLoader {
	friend class ProcessValidator;

private:
	bool bindLazy;

	uint64_t vdsoAddr; // if exec : Starting vaddr of the VDSO Image
	                   // if vdso : 0 [the vdso doesn't care where it is at]

	// map: name -> symtabID
	std::unordered_map<std::string, uint32_t> neededSyms;

public:
	ElfUserspaceLoader64(ElfFile64 *elffile,
	                   Kernel *parent,
	                   const std::string &name);

	virtual ~ElfUserspaceLoader64();

protected:
	int evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym> *map) override;

	void writeRelValue(uint64_t locAddr, uint64_t symAddr);
};


#endif  /* ELFUSERSPACELOADER64_H */
