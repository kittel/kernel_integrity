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

	std::vector<RelSym*> providedSyms; // symbols provided by this loader
	std::map<std::string, uint32_t> neededSyms; // first:name, second:symtabID

	std::vector<Elf64_Rel> rel;   // relocation entries of the file (.rel)
	std::vector<Elf64_Rela> rela; // dito (.rela)

public:
	ElfProcessLoader64(ElfFile64 *elffile,
	                   KernelManager *parent,
	                   std::string name="");

	virtual ~ElfProcessLoader64();

	virtual uint64_t getTextStart();
	virtual uint64_t getDataStart();
	virtual uint64_t getDataOff();
	virtual uint64_t getTextOff();
	virtual uint32_t getTextSize();
	virtual uint32_t getDataSize();

	virtual std::vector<RelSym*> getProvidedSyms();

protected:
	virtual void initProvidedSymbols();

	virtual uint64_t getVAForAddr(uint64_t addr, uint32_t shtID);


	virtual void applyLoadRel(std::unordered_map<std::string, RelSym*> *map);
	virtual int evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym*> *map);

	virtual void relocate(Elf64_Rela* rel,
	                      std::unordered_map<std::string, RelSym*> *map);
	virtual void relocate(Elf64_Rel* rel,
	                      std::unordered_map<std::string, RelSym*> *map);

	virtual void writeRelValue(uint64_t locAddr, uint64_t symAddr);

};


#endif  /* ELFPROCESSLOADER64_H */
