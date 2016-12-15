#ifndef KERNINT_ELFUSERSPACELOADER_H_
#define KERNINT_ELFUSERSPACELOADER_H_

#include "elffile.h"
#include "elfloader.h"

#include "taskmanager.h"

#include <unordered_map>

namespace kernint {

class ElfUserspaceLoader;
class ElfKernelLoader;
class Process;
class ProcessValidator;

class ElfUserspaceLoader : public ElfLoader {
	friend class ProcessValidator;
	friend class Process;

public:
	ElfUserspaceLoader(ElfFile *elffile, Kernel *kernel,
	                   const std::string &name);

	virtual ~ElfUserspaceLoader();

	/**
	 * Initialize the complete image
	 */
	void initImage() override;

	const std::string &getName() const override;
	const std::string &getBaseName() const;
	Kernel *getKernel() override;

	/**
	 * List of loaders that the current loader depends on for running.
	 */
	std::vector<ElfUserspaceLoader *> loadDependencies(Process *process);

protected:
	Kernel *kernel;

	/** full path of the elffile used in this loader */
	std::string name;

	/** only the filename of the elffile used in this loader */
	std::string baseName;

	SegmentInfo textSegmentInfo;
	SegmentInfo dataSegmentInfo;

	SectionInfo heapSection;  // handler for optional heap segment

	// symbols provided by this elf
	std::vector<ElfSymbol> getSymbols() const;

	/** copy .text etc to text segment */
	void initText() override;

	/** create data segment vector as origin for copies */
	void initData() override;

	SectionInfo *getSegmentForAddress(uint64_t addr);

	bool isCodeAddress(uint64_t addr) override;
	bool isDataAddress(uint64_t addr) override;
	bool isDataAddress(uint64_t addr, Process *process);

	virtual bool isTextOffset(uint64_t off);
	virtual bool isDataOffset(uint64_t off);
	bool isDataOffset(uint64_t off, Process *process);

	virtual int evalLazy(uint64_t addr,
	                     std::unordered_map<std::string, ElfSymbol> *map) = 0;

	void updateSectionInfoMemAddress(SectionInfo& info) override;
};

} // namespace kernint

#include "elfuserspaceloader64.h"

#endif
