#ifndef ELFFILE_H
#define ELFFILE_H

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <fcntl.h>
#include <cstring>

#include <sys/mman.h>

#include <map>
#include <memory>
#include <vector>

class ElfLoader;
class ElfModuleLoader;
class ElfKernelLoader;
class ElfProcessLoader;
class Kernel;
class SymbolManager;
class Process;

/* This class represents a symbol a loader may export for relocation */
class RelSym {
public:
	std::string name;          // name of the symbol
	uint64_t value;            // final vaddr after loading
	uint8_t info;              // corresponding type and sym in parent
	uint32_t shndx;            // linked section index in parent

	RelSym();
	RelSym(const std::string &, uint64_t, uint8_t, uint32_t);
	~RelSym();
};


class SectionInfo {
public:
	SectionInfo();
	SectionInfo(const std::string &segName,
	            uint32_t segID,
	            uint8_t *i,
	            uint64_t a,
	            uint32_t s);
	virtual ~SectionInfo();

	std::string segName;  // name of the segment, init with first sec name
	uint32_t segID;       // section ID in SHT
	uint8_t *index;       // section offset from beginning of ELF file
	                      // if dereferenced contains data of the section
	uint8_t *memindex;    // target virtual address in process image
	uint32_t size;        // size of the section content (in bytes?)

	bool containsElfAddress(uint64_t address);
	bool containsMemAddress(uint64_t address);

private:
	SectionInfo(uint8_t *i, uint32_t s);
};

class SegmentInfo {
public:
	SegmentInfo();
	SegmentInfo(uint32_t p_type,
	            uint32_t p_flags,
	            uint64_t p_offset,
	            uint8_t *p_vaddr,
	            uint8_t *p_paddr,
	            uint64_t p_filesz,
	            uint64_t p_memsz,
	            uint64_t p_align);

	virtual ~SegmentInfo();

	uint32_t type;
	uint32_t flags;
	uint64_t offset;
	uint8_t *vaddr;
	uint8_t *paddr;
	uint64_t filesz;
	uint64_t memsz;
	uint64_t align;
};

class ElfFile {
public:
	enum class ElfType { ELFTYPENONE, ELFTYPE32, ELFTYPE64 };

	enum class ElfProgramType {
		ELFPROGRAMTYPENONE,
		ELFPROGRAMTYPEKERNEL,
		ELFPROGRAMTYPEMODULE,
		ELFPROGRAMTYPEEXEC  //!< Type for loading executables
	};

	virtual ~ElfFile();

	virtual int getNrOfSections() = 0;

	virtual SectionInfo findSectionWithName(const std::string &sectionName) = 0;
	virtual SectionInfo findSectionByID(uint32_t sectionID) = 0;
	virtual bool isCodeAddress(uint64_t address) = 0;
	virtual bool isDataAddress(uint64_t address) = 0;
	virtual std::string sectionName(int sectionID) = 0;

	virtual SegmentInfo findCodeSegment() = 0;
	virtual SegmentInfo findDataSegment() = 0;

	virtual uint64_t findAddressOfVariable(const std::string &symbolName) = 0;

	virtual uint8_t *sectionAddress(int sectionID) = 0;
	virtual uint64_t sectionAlign(int sectionID) = 0;

	virtual std::string symbolName(uint32_t index) = 0;

	virtual ElfType getType();
	virtual ElfProgramType getProgramType();

	std::string getFilename();
	void printSymbols();

	uint8_t *getFileContent();
	size_t getFileSize();

	int getFD();

	/**
	 * Elffile-from-buffer factory method.
	 */
	static ElfFile *loadElfFileFromBuffer(uint8_t *buf, size_t size,
	                                      SymbolManager *symspace) throw();

	/**
	 * Main elffile factory method.
	 */
	static ElfFile *loadElfFile(const std::string &filename,
	                            SymbolManager *symspace) throw();

	/**
	 * Parse this elf file as a kernel blob.
	 */
	virtual ElfKernelLoader *parseKernel() = 0;

	/**
	 * Parse this elf file as a kernel module associated with a given kernel.
	 */
	virtual ElfModuleLoader *parseKernelModule(const std::string &name,
	                                           Kernel *kernel) = 0;

	/**
	 * Parse this elf file as a executable/library
	 * associated with a given process.
	 */
	virtual ElfProcessLoader *parseProcess(const std::string &name,
	                                       Process *process,
	                                       Kernel *kernel) = 0;

	virtual bool isRelocatable() = 0;
	virtual void applyRelocations(ElfModuleLoader *loader) = 0;
	virtual bool isDynamic() = 0;
	virtual bool isExecutable() = 0;

	virtual std::vector<std::string> getDependencies() = 0;
	virtual std::vector<RelSym> getSymbols() = 0;

	virtual void getRelEntries(std::vector<Elf64_Rel> &ret) = 0;
	virtual void getRelaEntries(std::vector<Elf64_Rela> &ret) = 0;

	uint32_t shstrindex;
	uint32_t symindex;
	uint32_t strindex;

	SymbolManager *symbols;

protected:
	ElfFile(FILE *fd,
	        size_t fileSize,
	        uint8_t *fileContent,
	        ElfType type,
	        ElfProgramType programType,
	        SymbolManager *symspace);

	FILE *fd;
	size_t fileSize;
	uint8_t *fileContent;
	ElfType type;
	ElfProgramType programType;

	std::string filename;

	typedef std::map<std::string, uint64_t> SymbolNameMap;
	SymbolNameMap symbolNameMap;
};

#include "elffile64.h"

#endif /* ELFFILE_H */
