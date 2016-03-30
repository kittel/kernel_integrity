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
 * should be able to bytewise compare the actual memory with an instance of this
 * class.
 */
class ElfLoader {
	friend class ElfKernelLoader;
	friend class ElfModuleLoader;
	friend class KernelValidator;
	friend class ElfProcessLoader;
	friend class ProcessValidator;
	friend class ParavirtPatcher;
	friend class Process;

public:
	virtual ~ElfLoader();

	virtual const std::string &getName() const = 0;
	virtual Kernel *getKernel() = 0;
	virtual void updateSectionInfoMemAddress(SectionInfo &info) = 0;

	virtual void parse();

protected:
	ElfLoader(ElfFile *elffile);

	ElfFile *elffile;         // Wrapped ElfFile, provides to file and seg
	Instance *debugInstance;  // Wrapped debug instance of the file

	std::vector<uint8_t> jumpTable;
	std::vector<uint8_t> roData;

	std::map<uint64_t, int32_t> jumpEntries;
	std::set<uint64_t> jumpDestinations;
	std::set<uint64_t> smpOffsets;

	SectionInfo textSegment;  // The first big memory segment
	SectionInfo dataSection;  // The second big memory segment
	SectionInfo bssSection;   // The last memory segment
	SectionInfo roDataSection;

	std::vector<uint8_t> textSegmentContent;
	std::vector<uint8_t> dataSegmentContent;

	void applyMcount(const SectionInfo &info, ParavirtPatcher *patcher);
	void applyAltinstr(ParavirtPatcher *patcher);
	void applySmpLocks();
	void applyJumpEntries(uint64_t jumpStart,
	                      uint32_t numberOfEntries,
	                      ParavirtPatcher *patcher);


	/**
	 * Load sections of this elf file.
	 */
	virtual void initText() = 0;
	virtual void initData() = 0;

	virtual bool isCodeAddress(uint64_t addr);
	virtual bool isDataAddress(uint64_t addr) = 0;
};

#include "elfkernelloader.h"
#include "elfmoduleloader.h"
#include "elfprocessloader.h"

#endif /* ELFLOADER_H */
