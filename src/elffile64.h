#ifndef KERNINT_ELFFILE64_H_
#define KERNINT_ELFFILE64_H_

#include "elffile.h"

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <fcntl.h>
#include <cstring>

#include <sys/mman.h>

#include <map>

namespace kernint {

class Process;


class ElfFile64 : public ElfFile {
public:
	ElfFile64(FILE* fd, size_t fileSize, uint8_t* fileContent);
	virtual ~ElfFile64();

	unsigned int getNrOfSections() const override;

	const SectionInfo &findSectionWithName(const std::string &sectionName) const override;
	const SectionInfo &findSectionByID(uint32_t sectionID) const override;
	const SectionInfo *findSectionByOffset(size_t offset) const override;

	bool isCodeAddress(uint64_t address) override;
	bool isDataAddress(uint64_t address) override;

	std::string sectionName(int sectionID) const override;
	uint8_t *sectionAddress(int sectionID) override;
	uint64_t sectionAlign(int sectionID) override;

	const SegmentInfo &findCodeSegment() const override;
	const SegmentInfo &findDataSegment() const override;
	const SegmentInfo &findSegmentByVaddr(const Elf64_Addr addr) const;

	std::string dynSymbolName(uint64_t offset) const override;
	std::string symbolName(uint32_t index, uint32_t strindex) const override;

	void addSymbolsToStore(SymbolManager *store, uint64_t memindex) const override;

	uint64_t entryPoint() const override;

	ElfKernelLoader *parseKernel() override;
	ElfModuleLoader *parseKernelModule(const std::string &name,
	                                   Kernel *kernel) override;
	ElfUserspaceLoader *parseUserspace(const std::string &name,
	                                   Kernel *kernel,
	                                   Process *process) override;

	bool isRelocatable() const override;
	void applyRelocations(ElfLoader *loader,
	                      Kernel *kernel,
	                      Process *process=nullptr) override;
	bool isDynamic() const override;
	bool isDynamicLibrary() const override;
	bool isExecutable() const override;

	std::vector<ElfSymbol> getSymbols(bool loadDbg) const override;

	std::vector<std::string> getDependencies() override;

	Elf64_Ehdr *elf64Ehdr;
	Elf64_Shdr *elf64Shdr;
	Elf64_Phdr *elf64Phdr;

private:
	void applyRelaOnSection(uint32_t relSectionID,
	                        ElfLoader *loader,
	                        Kernel *kernel,
	                        Process *process);
};

} // namespace kernint

#endif
