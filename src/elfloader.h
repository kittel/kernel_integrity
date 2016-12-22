#ifndef KERNINT_ELFLOADER_H_
#define KERNINT_ELFLOADER_H_

#include "elffile.h"

#include "elfmodule.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

#include "kernel_headers.h"

#include <vector>
#include <map>
#include <set>

namespace kernint {

class ParavirtPatcher;
class Kernel;

/**
 * An ElfLoader is the "working copy" of some elf file.
 * This equals the memory image.
 * A process has multiple file mappings, each of those is a Loader.
 *
 * After a full initialization (depending on the type of ELF file) one
 * should be able to bytewise compare the actual memory with an instance of
 * this class.
 */
class ElfLoader {
public:
	virtual ~ElfLoader() = default;

	virtual const std::string &getName() const = 0;
	virtual Kernel *getKernel() = 0;
	virtual void updateSectionInfoMemAddress(SectionInfo &info) = 0;

	virtual void initImage();

	const std::vector<uint8_t> &getTextSegment() const;
	const std::vector<uint8_t> &getDataSegment() const;

	virtual bool isCodeAddress(uint64_t addr);
	virtual bool isDataAddress(uint64_t addr) = 0;

	SectionInfo textSegment;  // The first big memory segment
	SectionInfo dataSection;  // The second big memory segment
	SectionInfo bssSection;   // The last memory segment
	SectionInfo roDataSection;

	/**
	 * Elf file where the loaded information came from .
	 */
	ElfFile *elffile;

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

} // namespace kernint

#endif
