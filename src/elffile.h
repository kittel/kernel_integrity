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
class ElfLoader32;
class ElfLoader64;

class KernelManager;

class SegmentInfo{

	public:
		SegmentInfo();
    	SegmentInfo(std::string segName, char * i, 
				uint64_t a, uint32_t s);
		virtual ~SegmentInfo();

		std::string segName;
		char * index;
		char * memindex;
    	uint64_t address;
    	uint32_t size;

	private:
    	SegmentInfo(char * i, uint32_t s);
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
		virtual uint64_t findAddressOfVariable(std::string symbolName) = 0;
		virtual ElfType getType();
		void printSymbols();
		char* getFileContent();
		int getFD();

		static ElfFile* loadElfFile(std::string filename) throw();
		virtual ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                            KernelManager* parent = 0) = 0;

		virtual bool isRelocatable() = 0;

		uint32_t shstrindex;
    	uint32_t symindex;
		uint32_t strindex;

	protected:

		ElfFile(FILE* fd, size_t fileSize, char* fileContent, ElfType type);
		FILE* fd;
		size_t fileSize;
		char* fileContent;
		ElfType type;
		std::string filename;

		typedef std::map<std::string, uint64_t> SymbolNameMap;
		SymbolNameMap symbolNameMap;
};

class ElfFile32 : public ElfFile {
	public:
		ElfFile32(FILE* fd, size_t fileSize, char* fileContent);
		virtual ~ElfFile32();

		SegmentInfo findSegmentWithName(std::string sectionName);
		uint64_t findAddressOfVariable(std::string symbolName);

		ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                    KernelManager* parent = 0);

		bool isRelocatable();
	protected:
};


class ElfFile64 : public ElfFile {
	public:
		ElfFile64(FILE* fd, size_t fileSize, char* fileContent);
		virtual ~ElfFile64();

		SegmentInfo findSegmentWithName(std::string sectionName);
		uint64_t findAddressOfVariable(std::string symbolName);

		ElfLoader* parseElf(ElfFile::ElfProgramType type,
		                    KernelManager* parent = 0);

		bool isRelocatable();

        Elf64_Ehdr * elf64Ehdr;
        Elf64_Shdr * elf64Shdr;
	protected:

	private:
};

#endif /* ELFFILE_H */
