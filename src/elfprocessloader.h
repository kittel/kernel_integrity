#ifndef ELFPROCESSLOADER_H
#define ELFPROCESSLOADER_H

#include "elfloader.h"

#include <unordered_map>

// The beauty of forward declarations
class ElfProcessLoader;
class ElfKernelLoader;

/* This class represents a symbol a loader may export for relocation */
class RelSym {
public:
	std::string name;          // name of the symbol
	uint64_t value;            // final vaddr after loading
	uint8_t info;              // corresponding type and sym in parent
	uint32_t shndx;            // linked section index in parent
	ElfProcessLoader* parent;  // lib in which this sym is defined

	RelSym(std::string, uint64_t, uint8_t, uint32_t, ElfProcessLoader *);
	~RelSym();
};

class ElfProcessLoader : public ElfLoader {
	friend class ProcessValidator;

public:
	ElfProcessLoader(ElfFile* elffile, KernelManager* parent, std::string name);

	virtual ~ElfProcessLoader();

	virtual void parseElfFile();  // Initialize the complete image

	virtual std::string getName();

protected:
	std::string execName;
	KernelManager *kernel;

	void loadDependencies();

	SegmentInfo textSegmentInfo;
	SegmentInfo dataSegmentInfo;

	SectionInfo heapSection;  // handler for optional heap segment

	std::vector<uint8_t> dataSegmentContent;  // actual dataSegment data
	std::vector<uint8_t> heapSegmentContent;

	ElfFile *getLibraryWithName(std::string name);
	//virtual std::vector<uint8_t> *buildSegfromLib(ElfFile *lib);

	virtual void initProvidedSymbols() = 0;

	void initText();
	void initData();

	virtual void applyLoadRel(std::unordered_map<std::string, RelSym*>* map) = 0;
	virtual std::vector<RelSym*> getProvidedSyms() = 0;
	virtual void setHeapSegment(SectionInfo* heap) = 0;

	uint64_t getHeapStart();

	virtual uint64_t getTextStart() = 0;
	virtual uint64_t getDataStart() = 0;
	virtual uint64_t getDataOff() = 0;
	virtual uint64_t getTextOff() = 0;
	virtual uint32_t getTextSize() = 0;
	virtual uint32_t getDataSize() = 0;

	ElfProcessLoader* getExecForAddress(uint64_t);
	SectionInfo* getSegmentForAddress(uint64_t addr);

	virtual bool isCodeAddress(uint64_t addr);
	virtual bool isDataAddress(uint64_t addr);

	virtual bool isTextOffset(uint64_t off);
	virtual bool isDataOffset(uint64_t off);
	virtual void updateMemIndex(uint64_t addr, uint8_t segNr) = 0;

	virtual int evalLazy(uint64_t addr,
	                     std::unordered_map<std::string, RelSym*>* map) = 0;

	virtual void updateSectionInfoMemAddress(SectionInfo& info);
	virtual void addSymbols();
};

#include "elfprocessloader64.h"

#endif
