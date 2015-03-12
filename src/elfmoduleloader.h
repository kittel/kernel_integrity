#ifndef ELFMODULELOADER_H
#define ELFMODULELOADER_H

#include "elfloader.h"
class ElfModuleLoader : public ElfLoader {
	public:
		ElfModuleLoader(ElfFile* elffile, 
		        std::string name = "", 
		        KernelManager* parent = 0);
		virtual ~ElfModuleLoader();

		virtual void applyRelocationsOnSection(uint32_t relSectionID) = 0;
		std::string getName();
	protected:
		void updateSegmentInfoMemAddress(SegmentInfo &info);
		uint8_t * findMemAddressOfSegment(std::string segName);
		
		virtual void initText();
		virtual void initData();
		virtual void addSymbols() = 0;

		void loadDependencies();
		
		bool isDataAddress(uint64_t addr);

		std::string modName;
		KernelManager* parent;

};

#include "elfmoduleloader32.h"
#include "elfmoduleloader64.h"

#endif  /* ELFMODULELOADER_H */
