#ifndef ELFPROCESSLOADER_H
#define ELFPROCESSLOADER_H

#include "elffile.h"
#include "elfloader.h"

#include "taskmanager.h"

#include <unordered_map>

// The beauty of forward declarations
class ElfProcessLoader;
class ElfKernelLoader;
class Process;
class ProcessValidator;

class ElfProcessLoader : public ElfLoader {
	friend class ProcessValidator;
	friend class Process;

public:
	ElfProcessLoader(ElfFile *elffile, Kernel *kernel,
	                 const std::string &name);

	virtual ~ElfProcessLoader();

	void parse() override;  // Initialize the complete image

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

	void initText() override;
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

	virtual void updateSectionInfoMemAddress(SectionInfo& info);
};

#include "elfprocessloader64.h"

#endif
