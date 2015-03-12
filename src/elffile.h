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

class ElfLoader;
class ElfModuleLoader;

class KernelManager;

class SegmentInfo{

	public:
		SegmentInfo();
    	SegmentInfo(std::string segName, uint32_t segID, uint8_t * i, 
				uint64_t a, uint32_t s);
		virtual ~SegmentInfo();

		std::string segName;
		uint32_t    segID;
		uint8_t *   index;
		uint8_t *   memindex;
    	uint32_t    size;

		bool containsElfAddress(uint64_t address);
		bool containsMemAddress(uint64_t address);

	private:
    	SegmentInfo(uint8_t * i, uint32_t s);
};


class ElfFile{
	
	public:

		typedef enum {
			ELFTYPENONE = 0,
			ELFTYPE32,
			ELFTYPE64
		} ElfType;

		typedef enum {
			ELFPROGRAMTYPENONE = 0,
			ELFPROGRAMTYPEKERNEL,
			ELFPROGRAMTYPEMODULE
		} ElfProgramType;

		virtual ~ElfFile();

		virtual SegmentInfo findSegmentWithName(std::string sectionName) = 0;
		virtual SegmentInfo findSegmentByID(uint32_t sectionID) = 0;
		virtual std::string segmentName(int sectionID) = 0;

		virtual uint64_t findAddressOfVariable(std::string symbolName) = 0;

		virtual uint8_t *segmentAddress(int sectionID) = 0;

		virtual std::string symbolName(uint32_t index) = 0;

		virtual ElfType getType();
		void printSymbols();
		uint8_t* getFileContent();
		int getFD();

		static ElfFile* loadElfFile(std::string filename) throw();
		virtual ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                            std::string name = "",
		                            KernelManager* parent = 0) = 0;

		virtual bool isRelocatable() = 0;
		virtual void applyRelocations(ElfModuleLoader *loader) = 0;

		uint32_t shstrindex;
    	uint32_t symindex;
		uint32_t strindex;

	protected:

		ElfFile(FILE* fd, size_t fileSize, uint8_t* fileContent, ElfType type);
		FILE* fd;
		size_t fileSize;
		uint8_t* fileContent;
		ElfType type;
		std::string filename;

		typedef std::map<std::string, uint64_t> SymbolNameMap;
		SymbolNameMap symbolNameMap;

};

#include <elffile32.h>
#include <elffile64.h>


#endif /* ELFFILE_H */
