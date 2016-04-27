#ifndef ELFUSERSPACELOADER_H
#define ELFUSERSPACELOADER_H

#include "elffile.h"
#include "elfloader.h"

#include "taskmanager.h"

#include <unordered_map>

// The beauty of forward declarations
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

	void initImage() override;  // Initialize the complete image

	const std::string &getName() const override;
	Kernel *getKernel() override;

protected:
	Kernel *kernel;

	std::string name;

	void loadDependencies();

	SegmentInfo textSegmentInfo;
	SegmentInfo dataSegmentInfo;

	SectionInfo heapSection;  // handler for optional heap segment

	// symbols provided by this elf
	std::vector<RelSym> getSymbols() const;

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
	                     std::unordered_map<std::string, RelSym> *map) = 0;

	void updateSectionInfoMemAddress(SectionInfo& info) override;
};

#include "elfuserspaceloader64.h"

#endif
