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

	SectionInfo findSectionWithName(std::string sectionName);
	SectionInfo findSectionByID(uint32_t sectionID);
	bool isCodeAddress(uint64_t address);
	bool isDataAddress(uint64_t address);

	std::string sectionName(int sectionID);
	uint8_t *sectionAddress(int sectionID);
	uint64_t sectionAlign(int sectionID);

	SegmentInfo findCodeSegment();
	SegmentInfo findDataSegment();

	std::string symbolName(uint32_t index);

	uint64_t findAddressOfVariable(std::string symbolName);

	ElfLoader* parseElf(ElfFile::ElfProgramType type,
	                    std::string name = "",
	                    KernelManager* parent = 0);

	bool isRelocatable();
	void applyRelocations(ElfModuleLoader *loader);
	virtual bool isDynamic();
	std::vector<std::string> getDependencies();

	virtual bool isExecutable();

	Elf64_Ehdr * elf64Ehdr;
	Elf64_Shdr * elf64Shdr;
	Elf64_Phdr * elf64Phdr;

	int getNrOfSections();

	template<typename T>
	void getRelEntries(std::vector<T> &ret, uint32_t type);
	void getRelEntries(std::vector<Elf64_Rel> &ret);
	void getRelaEntries(std::vector<Elf64_Rela> &ret);

protected:

private:
};

#endif /* ELFFILE64_H */
