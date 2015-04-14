#ifndef ELFFILE32_H
#define ELFFILE32_H

#include <elffile.h>

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <fcntl.h>
#include <cstring>

#include <sys/mman.h>

#include <map>

class ElfFile32 : public ElfFile {
	public:
		ElfFile32(FILE* fd, size_t fileSize, uint8_t* fileContent);
		virtual ~ElfFile32();

		SegmentInfo findSegmentWithName(std::string sectionName);
		SegmentInfo findSegmentByID(uint32_t sectionID);
		bool isCodeAddress(uint64_t address);
		bool isDataAddress(uint64_t address);
		std::string segmentName(int sectionID);
		uint8_t *segmentAddress(int sectionID);

		std::string symbolName(uint32_t index);

		uint64_t findAddressOfVariable(std::string symbolName);

		ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                    std::string name = "",
		                    KernelManager* parent = 0);

		bool isRelocatable();
		void applyRelocations(ElfModuleLoader *loader);
	protected:
};

#endif /* ELFFILE32_H */
