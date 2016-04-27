#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "elffile.h"

#include "elfmodule.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

#include "kernel_headers.h"

#include <vector>
#include <map>
#include <set>

class ParavirtPatcher;
class Kernel;

/**
 * An ElfLoader is a memory representation we construct from the whitelisted
 * file. After a full initialization (depending on the type of ELF file) one
 * should be able to bytewise compare the actual memory with an instance of
 * this class.
 */
class ElfLoader {
public:
	virtual ~ElfLoader() = default;

	virtual const std::string &getName() const = 0;
	virtual Kernel *getKernel() = 0;
	virtual void updateSectionInfoMemAddress(SectionInfo &info) = 0;

	virtual void parse();

	const std::vector<uint8_t> &getTextSegment();
	const std::vector<uint8_t> &getDataSegment();

	virtual bool isCodeAddress(uint64_t addr);
	virtual bool isDataAddress(uint64_t addr) = 0;

	ElfFile *elffile;         // Wrapped ElfFile, provides to file and seg

	SectionInfo textSegment;  // The first big memory segment
	SectionInfo dataSection;  // The second big memory segment
	SectionInfo bssSection;   // The last memory segment
	SectionInfo roDataSection;

protected:
	ElfLoader(ElfFile *elffile);

	Instance *debugInstance;  // Wrapped debug instance of the file

	std::vector<uint8_t> jumpTable;
	std::vector<uint8_t> roData;

	/**
	 * memory content of the text segment,
	 * this chunk should exist with the exact same data within the VM.
	 */
	std::vector<uint8_t> textSegmentContent;

	/**
	 * memory content of the raw data segment.
	 * this chunk is loaded in a process image and then updated
	 * with changes for e.g. relocations.
	 */
	std::vector<uint8_t> dataSegmentContent;

	/**
	 * Load sections of this elf file.
	 */
	virtual void initText() = 0;
	virtual void initData() = 0;
};

#endif /* ELFLOADER_H */
