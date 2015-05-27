#ifndef ELFPROCESSLOADER_H
#define ELFPROCESSLOADER_H

#include "elfloader.h"
//#include "processmanager.h"

class ElfProcessLoader : public ElfLoader {
	public:
		ElfProcessLoader(ElfFile* elffile, std::string name);
		virtual ~ElfProcessLoader();
		virtual ElfLoader* getExecForAddress(uint64_t address);
		virtual uint8_t* getImageForAddress(uint64_t addr, uint32_t offset);
		virtual SegmentInfo* getSegmentForAddress(uint64_t addr);
		std::string getName();
		virtual uint64_t getHeapStart();
		virtual void printImage();
		virtual uint64_t getStartAddr();
		virtual void supplyVDSO(ElfProcessLoader *vdso);
		virtual void supplyLibraries(std::vector<ElfProcessLoader*> *libs);

	protected:
		std::string execName;

		 ElfFile* getLibraryWithName(std::string name);
//		virtual std::vector<uint8_t>* buildSegfromLib(ElfFile *lib);

//		virtual void initSuppliedLibraries(std::string name);
//		virtual void initProcessImage();

		virtual void initText();
		virtual void initData();
		virtual void addSymbols();
//		virtual void parseElfFile();

		virtual void updateSegmentInfoMemAddress(SegmentInfo &info);
//		virtual bool isCodeAddress(uint64_t addr);
		virtual bool isDataAddress(uint64_t addr);
		virtual uint8_t * findMemAddressOfSegment(std::string segName);
//		virtual void loadDependencies();

//		virtual void applyLoadTimeRelocs();
//		virtual void applyRunTimeReloc(std::string symname);
//		virtual void applyRunTimeRelocs();
//		virtual uint64_t getOffASLR(uint8_t type);
//		virtual void applyDynamicChanges();
		
};

//#include "elfprocessloader32.h"
#include "elfprocessloader64.h"

#endif
