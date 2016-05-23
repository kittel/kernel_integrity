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

	unsigned int getNrOfSections() const override;

	SectionInfo findSectionWithName(const std::string &sectionName) const override;
	SectionInfo findSectionByID(uint32_t sectionID) const override;
	bool isCodeAddress(uint64_t address) override;
	bool isDataAddress(uint64_t address) override;

	std::string sectionName(int sectionID) const override;
	uint8_t *sectionAddress(int sectionID) override;
	uint64_t sectionAlign(int sectionID) override;

	SegmentInfo findCodeSegment() override;
	SegmentInfo findDataSegment() override;

	std::string symbolName(uint32_t index, uint32_t strindex) const override;

	void addSymbolsToStore(SymbolManager *store, uint64_t memindex) const override;

	uint64_t findAddressOfVariable(const std::string &symbolName) override;

	ElfKernelLoader *parseKernel() override;
	ElfModuleLoader *parseKernelModule(const std::string &name,
	                                   Kernel *kernel) override;
	ElfUserspaceLoader *parseUserspace(const std::string &name,
	                                   Kernel *kernel) override;

	bool isRelocatable() const override;
	void applyRelocations(ElfLoader *loader,
	                      Kernel *kernel,
	                      Process *process=nullptr) override;
	bool isDynamic() const override;
	bool isDynamicLibrary() const override;
	bool isExecutable() const override;

	std::vector<RelSym> getSymbols() const override;

	std::vector<std::string> getDependencies() override;

	Elf64_Ehdr *elf64Ehdr;
	Elf64_Shdr *elf64Shdr;
	Elf64_Phdr *elf64Phdr;

	template<typename T>
	std::vector<T> getRelocationEntries(uint32_t type) const;

	std::vector<Elf64_Rel> getRelEntries() const override;
	std::vector<Elf64_Rela> getRelaEntries() const override;

private:
	void applyRelaOnSection(uint32_t relSectionID,
	                        ElfLoader *loader,
	                        Kernel *kernel,
	                        Process *process);
};

#endif /* ELFFILE64_H */
