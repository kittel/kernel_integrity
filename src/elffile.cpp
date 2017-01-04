#include "elffile.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

namespace kernint {

ElfSymbol::ElfSymbol()
	:
	name{},
	value{0},
	info{0},
	shndx{0},
	section{nullptr},
	segment{nullptr} {}

ElfSymbol::ElfSymbol(const std::string &name,
                     uint64_t value,
                     uint8_t info,
                     uint32_t shndx,
                     const SectionInfo *section,
                     const SegmentInfo *segment)
	:
	name{name},
	value{value},
	info{info},
	shndx{shndx},
	section{section},
	segment{segment} {}

ElfSymbol::~ElfSymbol() {}

SectionInfo::SectionInfo()
	:
	name{},
	secID{0xffffffff},
	index{0},
	memindex{0},
	size{0},
	flags{0} {}

SectionInfo::SectionInfo(const std::string &name,
                         uint32_t secID,
                         uint64_t offset,
                         uint8_t *index,
                         uint64_t memindex,
                         uint64_t size,
                         uint64_t flags)
	:
	name{name},
	secID{secID},
	offset{offset},
	index{index},
	memindex{memindex},
	size{size},
	flags{flags} {}

SectionInfo::~SectionInfo() {}

bool SectionInfo::containsElfAddress(uint64_t address){
	uint64_t addr = reinterpret_cast<uint64_t>(this->index);
	return (address >= addr && address <= addr + this->size);
}

bool SectionInfo::containsMemAddress(uint64_t address){
	uint64_t addr = this->memindex;
	return (address >= addr && address <= addr + this->size);
}

void SectionInfo::print(){
	std::cout << "Section: " << name << std::endl <<
	    "\tid:\t" << secID << std::endl <<
	    "\toffset:\t" << offset << std::endl <<
	    "\tindex:\t" << (uint64_t) index << std::endl <<
	    "\tmemindex:\t" << memindex << std::endl <<
	    "\tsize:\t" << size << std::endl << std::endl;
}

SegmentInfo::SegmentInfo()
	:
	type{0},
	flags{0},
	offset{0},
	vaddr{0},
	paddr{0},
	filesz{0},
	memsz{0},
	align{0} {}

SegmentInfo::SegmentInfo(uint32_t p_type,
                         uint32_t p_flags,
                         uint64_t p_offset,
                         uint64_t p_vaddr,
                         uint64_t p_paddr,
                         uint64_t p_filesz,
                         uint64_t p_memsz,
                         uint64_t p_align):
	type  {p_type},
	flags {p_flags},
	offset{p_offset},
	vaddr {p_vaddr},
	paddr {p_paddr},
	filesz{p_filesz},
	memsz {p_memsz},
	align {p_align} {}

SegmentInfo::~SegmentInfo() {}

ElfFile::ElfFile(FILE *fd, size_t fileSize, uint8_t *fileContent,
                 ElfType type,
                 ElfProgramType programType)
	:
	shstrindex{0},
	fd{fd},
	fileSize{fileSize},
	fileContent{fileContent},
	type{type},
	programType{programType},
	filename{""},
	doLazyBind{false} // < TODO set to true once the "this elf doesn't lazybind" detection works
{}

ElfFile::~ElfFile(){
	if(this->fileContent != nullptr){
		munmap(this->fileContent, this->fileSize);
	}
	fclose(this->fd);
}

void ElfFile::parseDwarf() {
	try {
		DwarfParser::parseDwarfFromFD(this->getFD(), this->symbols);
	} catch(DwarfException &e) {
		//std::cout << e.what() << std::endl;
		e.what();
	}
}

ElfFile *ElfFile::loadElfFile(const std::string &filename) {
	FILE *fd = nullptr;
	fd       = fopen(filename.c_str(), "rb");

	if (fd == nullptr) {
		// std::cout << COLOR_RED << COLOR_BOLD
		//           << "File not found: " << filename
		//           << COLOR_RESET << std::endl;
		return nullptr;
	}

	char e_ident[SELFMAG];
	size_t nread = fread(e_ident, 1, sizeof(e_ident), fd);

	if (nread != SELFMAG or
	    e_ident[EI_MAG0] != ELFMAG0 or
	    e_ident[EI_MAG1] != ELFMAG1 or
	    e_ident[EI_MAG2] != ELFMAG2 or
	    e_ident[EI_MAG3] != ELFMAG3) {

		std::cout << "non-elf file: " << filename << std::endl;

		fclose(fd);
		return nullptr;
	}

	ElfFile *elfFile     = nullptr;
	size_t fileSize      = 0;
	uint8_t *fileContent = nullptr;

	// Go to the end of the file.
	if (fseek(fd, 0L, SEEK_END) == 0) {
		// Get the size of the file.
		fileSize = ftell(fd);

		// MMAP the file to memory
		fileContent = reinterpret_cast<uint8_t *>(
			mmap(
				0,
				fileSize,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE,
				fileno(fd),
				0
			)
		);
		if (fileContent == MAP_FAILED) {
			std::cout << "mmap failed" << std::endl;
			fclose(fd);
			throw ElfException{"MMAP failed!!!\n"};
		}
	}

	if (fileContent[4] == ELFCLASS64) {
		elfFile = new ElfFile64(fd, fileSize, fileContent);
	} else {
		fclose(fd);
		throw ElfException{"unsupported elfclass!\n"};
	}

	elfFile->fd          = fd;
	elfFile->fileSize    = fileSize;
	elfFile->fileContent = fileContent;
	elfFile->filename    = filename;

	return elfFile;
}

/* used for loading VDSO */
ElfFile* ElfFile::loadElfFileFromBuffer(const std::string &filename,
                                        uint8_t* buf, size_t size) {

	ElfFile* elfFile = 0;

	size_t fileSize = size;
	uint8_t* fileContent = buf;
	FILE* fd = fmemopen(fileContent, fileSize, "rb");

	if(fileContent[4] == ELFCLASS64) {
		elfFile = new ElfFile64(fd, fileSize, fileContent);
	}
	elfFile->fd = fd;

	elfFile->fileSize = fileSize;
	elfFile->fileContent = fileContent;
	elfFile->filename    = filename;

	return elfFile;
}

ElfFile* ElfFile::loadDebugVersion() const {
	ElfFile* dbg = nullptr;
	auto it = this->section_names.find(".note.gnu.build-id");
	if (it != this->section_names.end()) {
		auto buildIdSection = *(it->second);
		std::string buildID = hexStr(buildIdSection.index+16, buildIdSection.size-16);
		std::stringstream s;
		s << "/home/kittel/guest" << "/usr/lib/debug/.build-id/"
		  << buildID.substr(0,2) << "/" << buildID.substr(2) << ".debug";
		dbg = this->loadElfFile(s.str());
	}
	return dbg;
}


ElfFile::ElfType ElfFile::getType() { return this->type; }

ElfFile::ElfProgramType ElfFile::getProgramType() { return this->programType;}

int ElfFile::getFD() { return fileno(this->fd); }

void ElfFile::printSymbols(uint32_t symindex){
	uint8_t *elfEhdr = this->fileContent;

	if (elfEhdr[4] == ELFCLASS32) {
		// TODO
		std::cout << "can't print elfclass32 symbols" << std::endl;
	}
	else if (elfEhdr[4] == ELFCLASS64) {
		Elf64_Ehdr * elf64Ehdr;
		Elf64_Shdr * elf64Shdr;

		// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Ehdr *' increases required alignment from 1 to 8
		elf64Ehdr = (Elf64_Ehdr *) elfEhdr;
		// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Shdr *' increases required alignment from 1 to 8
		elf64Shdr = (Elf64_Shdr *) (elfEhdr + elf64Ehdr->e_shoff);

		uint32_t symSize = elf64Shdr[symindex].sh_size;
		// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Sym *' increases required alignment from 1 to 8
		Elf64_Sym *symBase = (Elf64_Sym *) (elfEhdr + elf64Shdr[symindex].sh_offset);

		std::string symbolName;
		std::string sectionName;
		uint32_t strindex = elf64Shdr[symindex].sh_link;

		// TODO: warning: cast from 'char *' to 'Elf64_Sym *' increases required alignment from 1 to 8
		for(Elf64_Sym * sym = symBase;
		    sym < (Elf64_Sym *) (((char*) symBase) + symSize) ;
		    sym++) {

			symbolName = this->symbolName(sym->st_name, strindex);
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

uint8_t* ElfFile::getFileContent() {
	return this->fileContent;
}

size_t ElfFile::getFileSize() {
	return this->fileSize;
}

std::string ElfFile::getFilename() {
	return this->filename;
}

} // namespace kernint
