#ifndef ELFPROCESSLOADER64_H
#define ELFPROCESSLOADER64_H

#include <algorithm>
#include <vector>
#include <unordered_map>
#include <elf.h>

#include "helpers.h"
#include "elfprocessloader.h"

#ifndef ASLROFFTYPE_M
#define ASLROFFTYPE_M

#define ASLR_BRK    1
#define ASLR_STACK  2
#define ASLR_VDSO   3

#endif //ASLROFFTYPE_M



/**
 * This class is a derivated ElfProcessLoader for use with 64-Bit Systems.
 * It holds a process image for validation, which is derived from the original
 * ELF by retracing the building process in the target system.
 *
 *  Important members inherited from higher classes:
 *
 *  protected:
 *      ElfFile                 *elffile;
 *      Instance                debugInstance;
 *      SectionInfo             textSegment;
 *-------------------------------------------------------
 *  containing the following members:
 *      std::string segName;    // name of the segment, init with first sec name
 *      uint32_t    segID;      // section ID in SHT
 *      uint8_t *   index;      // section offset from beginning of ELF file
 *                              // if dereferenced contains data of the section
 *      uint8_t *   memindex;   // target virtual address in process image
 *                                 _BEWARE_: in PIC this field is subject to
 *                                 _secure_ dynamic modifications by the loader
 *                                 to suit a given address space! It may not
 *                                 resemble the original entry in the whitelisted
 *                                 ELF-File.
 *      uint32_t    size;       // size of the section content
 *-------------------------------------------------------
 *
 *      std::vector<uint8_t>    textSegmentContent; // actual textSegment data
 */
class ElfProcessLoader64 : public ElfProcessLoader {
	friend class ProcessValidator;

private:
	bool bindLazy;

	uint64_t vdsoAddr; // if exec : Starting vaddr of the VDSO Image
	// if vdso : 0 [the vdso doesn't care where it is at]

	std::unordered_map<std::string, uint32_t> neededSyms; // first:name, second:symtabID

public:
	ElfProcessLoader64(ElfFile64 *elffile,
	                   Kernel *parent,
	                   const std::string &name,
	                   Process *proc);

	virtual ~ElfProcessLoader64();

	uint64_t getTextStart() override;
	uint64_t getDataStart() override;
	uint64_t getDataOff() override;
	uint64_t getTextOff() override;
	uint32_t getTextSize() override;
	uint32_t getDataSize() override;

protected:
	virtual uint64_t getVAForAddr(uint64_t addr, uint32_t shtID);

	virtual void applyLoadRel(ProcessValidator *val);
	int evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym> *map) override;

	void relocate(Elf64_Rela *rel);
	void relocate(Elf64_Rel *rel);

	void writeRelValue(uint64_t locAddr, uint64_t symAddr);
};


#endif  /* ELFPROCESSLOADER64_H */
