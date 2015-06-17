#ifndef ELFFILE64_H
#define ELFFILE64_H

#include <elffile.h>

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <fcntl.h>
#include <cstring>

#include <sys/mman.h>

#include <map>

class ElfFile64 : public ElfFile {
	public:
		ElfFile64(FILE* fd, size_t fileSize, uint8_t* fileContent);
		virtual ~ElfFile64();

		SegmentInfo findSegmentWithName(std::string sectionName);
		SegmentInfo findSegmentByID(uint32_t sectionID);
		bool isCodeAddress(uint64_t address);
		bool isDataAddress(uint64_t address);
		std::string segmentName(int sectionID);
		uint8_t *segmentAddress(int sectionID);
		uint64_t segmentAlign(int sectionID);

		std::string symbolName(uint32_t index);

		uint64_t findAddressOfVariable(std::string symbolName);

		ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                    std::string name = "",
		                    KernelManager* parent = 0);

		bool isRelocatable();
		void applyRelocations(ElfModuleLoader *loader);

        Elf64_Ehdr * elf64Ehdr;
        Elf64_Shdr * elf64Shdr;
		Elf64_Phdr * elf64Phdr;
		
		int getNrOfSections();

	protected:

	private:
};

#endif /* ELFFILE64_H */
