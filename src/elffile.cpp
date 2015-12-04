#include "elffile.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

RelSym::RelSym()
	:
	name{""},
	value{0},
	info{0},
	shndx{0} {}

RelSym::RelSym(const std::string &name,
               uint64_t value,
               uint8_t info,
               uint32_t shndx)
	:
	name(name),
	value(value),
	info(info),
	shndx(shndx) {}

RelSym::~RelSym() {}

SectionInfo::SectionInfo()
	:
	segName(),
	segID(0),
	index(0),
	memindex(0),
	size(0) {}

SectionInfo::SectionInfo(uint8_t *i, unsigned int s)
	:
	segName(),
	segID(),
	index(i),
	memindex(0),
	size(s) {}

SectionInfo::SectionInfo(const std::string &segName, uint32_t segID, uint8_t *i, uint64_t a, uint32_t s)
	:
	segName(segName),
	segID(segID),
	index(i),
	memindex((uint8_t*) a),
	size(s) {}

SectionInfo::~SectionInfo() {}

bool SectionInfo::containsElfAddress(uint64_t address){
	uint64_t addr = (uint64_t) this->index;
	if (address >= addr &&
	    address <= addr + this->size){
		return true;
	}
	return false;
}

bool SectionInfo::containsMemAddress(uint64_t address){
	uint64_t addr = (int64_t) this->memindex;
	if (address >= addr &&
	    address <= addr + this->size){
		return true;
	}
	return false;
}

SegmentInfo::SegmentInfo()
	:
	type(0),
	flags(0),
	offset(0),
	vaddr(0),
	paddr(0),
	filesz(0),
	memsz(0),
	align(0) {}

SegmentInfo::SegmentInfo(uint32_t p_type,
                         uint32_t p_flags,
                         uint64_t p_offset,
                         uint8_t* p_vaddr,
                         uint8_t* p_paddr,
                         uint64_t p_filesz,
                         uint64_t p_memsz,
                         uint64_t p_align):
	type  (p_type),
	flags (p_flags),
	offset(p_offset),
	vaddr (p_vaddr),
	paddr (p_paddr),
	filesz(p_filesz),
	memsz (p_memsz),
	align (p_align) {}

SegmentInfo::~SegmentInfo() {}

ElfFile::ElfFile(FILE *fd, size_t fileSize, uint8_t *fileContent,
                 ElfType type,
                 ElfProgramType programType,
                 SymbolManager *symspace)
	:
	shstrindex(0),
	symindex(0),
	strindex(0),
	symbols{symspace},
	fd(fd),
	fileSize(fileSize),
	fileContent(fileContent),
	type(type),
	programType(programType),
	filename("") {

	try {
		DwarfParser::parseDwarfFromFD(this->getFD(), this->symbols);
	} catch(DwarfException &e) {
		std::cout << e.what() << std::endl;
	}
#ifdef DEBUG
	std::cout << "Done loading elfFile" << std::endl;
#endif
}

ElfFile::~ElfFile(){
	if(this->fileContent != nullptr){
		munmap(this->fileContent, this->fileSize);
	}
	fclose(this->fd);
}

ElfFile* ElfFile::loadElfFile(const std::string &filename,
                              SymbolManager *symspace) throw(){
	FILE* fd = nullptr;
	fd = fopen(filename.c_str(), "rb");

	if(!fd){
		std::cout << COLOR_RED << COLOR_BOLD <<
		"File not found: " << filename <<
		COLOR_NORM << std::endl;
		exit(0);
	}

	ElfFile* elfFile = nullptr;

	size_t fileSize = 0;
	uint8_t* fileContent = nullptr;

	if (fd != nullptr) {
		/* Go to the end of the file. */
		if (fseek(fd, 0L, SEEK_END) == 0) {
			/* Get the size of the file. */
			fileSize = ftell(fd);

			//MMAP the file to memory
			fileContent = (uint8_t*) mmap(0, fileSize,
			                              PROT_READ | PROT_WRITE,
			                              MAP_PRIVATE, fileno(fd), 0);
			if (fileContent == MAP_FAILED) {
				std::cout << "mmap failed" << std::endl;
				throw ElfException("MMAP failed!!!\n");
			}
		}
	} else {
		std::cout << "cannot load file" << std::endl;
		throw ElfException("Cannot load file");
	}


	if(fileContent[4] == ELFCLASS64) {
		elfFile = new ElfFile64(fd, fileSize, fileContent, symspace);
	}
	elfFile->fd = fd;
	elfFile->fileSize = fileSize;
	elfFile->fileContent = fileContent;

	return elfFile;
}

ElfFile* ElfFile::loadElfFileFromBuffer(uint8_t* buf, size_t size,
                                        SymbolManager *symspace) throw() {

	ElfFile* elfFile = 0;

	size_t fileSize = size;
	uint8_t* fileContent = buf;
	FILE* fd = fmemopen(fileContent, fileSize, "rb");

	if(fileContent[4] == ELFCLASS64) {
		elfFile = new ElfFile64(fd, fileSize, fileContent, symspace);
	}
	elfFile->fd = fd;

	elfFile->fileSize = fileSize;
	elfFile->fileContent = fileContent;

	return elfFile;
}

ElfFile::ElfType ElfFile::getType() { return this->type; }

ElfFile::ElfProgramType ElfFile::getProgramType() { return this->programType;}

int ElfFile::getFD() { return fileno(this->fd); }

void ElfFile::printSymbols(){
	uint8_t *elfEhdr = this->fileContent;

	if (elfEhdr[4] == ELFCLASS32) {
		//TODO
	}
	else if (elfEhdr[4] == ELFCLASS64) {
		Elf64_Ehdr * elf64Ehdr;
		Elf64_Shdr * elf64Shdr;

		elf64Ehdr = (Elf64_Ehdr *) elfEhdr;
		elf64Shdr = (Elf64_Shdr *) (elfEhdr + elf64Ehdr->e_shoff);

		uint32_t symSize = elf64Shdr[this->symindex].sh_size;
		Elf64_Sym *symBase = (Elf64_Sym *) (elfEhdr + elf64Shdr[this->symindex].sh_offset);

		std::string symbolName;
		std::string sectionName;

		for(Elf64_Sym * sym = symBase;
		    sym < (Elf64_Sym *) (((char*) symBase) + symSize) ;
		    sym++) {

			symbolName = this->symbolName(sym->st_name);
			if (sym->st_shndx < SHN_LORESERVE) {
				sectionName =  this->sectionName(sym->st_shndx);
			} else {
				switch(sym->st_shndx){
				case SHN_UNDEF:
					sectionName = "*UND*";
					break;
				case SHN_LORESERVE:
					sectionName = "*LORESERVE*";
					break;
				case SHN_AFTER:
					sectionName = "*AFTER*";
					break;
				case SHN_HIPROC:
					sectionName = "*HIPROC*";
					break;
				case SHN_LOOS:
					sectionName = "*LOOS*";
					break;
				case SHN_HIOS:
					sectionName = "*HIOS*";
					break;
				case SHN_ABS:
					sectionName = "*ABS*";
					break;
				case SHN_COMMON:
					sectionName = "*COMMON*";
					break;
				case SHN_HIRESERVE:
					sectionName = "*HIRESERVE*";
					break;
				}
			}

			if (ELF64_ST_TYPE(sym->st_info) == STT_FUNC ||
			    ELF64_ST_TYPE(sym->st_info) == STT_OBJECT) {
				std::cout << "Symbol: " << std::hex << sym->st_value << std::dec
				          << " " << sectionName << " : " << symbolName
				          << " ( " << sym->st_size << " ) " << std::endl;
			}
		}
	}
}

uint8_t* ElfFile::getFileContent(){
	return this->fileContent;
}

size_t ElfFile::getFileSize(){
	return this->fileSize;
}

std::string ElfFile::getFilename(){
	return this->filename;
}
