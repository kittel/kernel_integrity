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

class ElfProcessLoader : public ElfLoader {
	friend class ProcessValidator;

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

	SectionInfo heapSection;  // handler for optional heap segment
	std::vector<uint8_t> dataSegmentContent;  // actual dataSegment data

	std::vector<RelSym> providedSyms; // symbols provided by this loader
	virtual std::vector<RelSym> getProvidedSyms();

	void initText() override;
	void initData() override;
	void initData(Process *proc);

	virtual void applyLoadRel(class ProcessValidator *val) = 0;

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
	virtual void addSymbols();

};

#include "elfprocessloader64.h"

#endif
