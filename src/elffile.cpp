#include "elffile.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

SegmentInfo::SegmentInfo(): segName(), index(0), memindex(0), address(0), size(0){}
SegmentInfo::SegmentInfo(char *i, unsigned int s):
				segName(), index(i), memindex(0), address(0), size(s){}
SegmentInfo::SegmentInfo(std::string segName, char *i, 
					uint64_t a, uint32_t s):
				segName(segName), index(i), memindex(0),
			   	address(a), size(s){}
SegmentInfo::~SegmentInfo(){}

ElfFile::ElfFile(FILE* fd, size_t fileSize, char* fileContent, ElfType type):
	shstrindex(0), symindex(0), strindex(0),
	fd(fd), fileSize(fileSize), fileContent(fileContent), type(type),
	filename(""), symbolNameMap(){
	
	try{
		DwarfParser::parseDwarfFromFD(this->getFD());
	}catch(DwarfException &e){
		std::cout << e.what() << std::endl;
	}
	//std::cout << "Done loading elfFile" << std::endl;
}

ElfFile::~ElfFile(){
    if(this->fileContent != NULL){
        munmap(this->fileContent, this->fileSize);
    }
    fclose(this->fd);
}

ElfFile* ElfFile::loadElfFile(std::string filename) throw(){

	ElfFile * elfFile = 0;

	FILE* fd;
	size_t fileSize;
	char* fileContent;

	fd = fopen(filename.c_str(), "rb");
    if (fd != NULL) {
        /* Go to the end of the file. */
        if (fseek(fd, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            fileSize = ftell(fd);

            //MMAP the file to memory
            fileContent = (char*) mmap(0, fileSize,
					PROT_READ | PROT_WRITE, MAP_PRIVATE, fileno(fd), 0);
            if (fileContent == MAP_FAILED) {
                throw ElfException("MMAP failed!!!\n");
            }
        }
    }else{
		throw ElfException("Cannot load file");
	}


    if(fileContent[4] == ELFCLASS32)
    {
        elfFile = new ElfFile32(fd, fileSize, fileContent);
    }
    else if(fileContent[4] == ELFCLASS64)
    {
    	elfFile = new ElfFile64(fd, fileSize, fileContent);
    }
    elfFile->fd = fd;
    elfFile->fileSize = fileSize;
    elfFile->fileContent = fileContent;

    return elfFile;
}

ElfFile::ElfType ElfFile::getType(){ return this->type; }

int ElfFile::getFD(){ return fileno(this->fd); }

ElfFile32::ElfFile32(FILE* fd, size_t fileSize, char* fileContent):
	ElfFile(fd, fileSize, fileContent, ELFTYPE32){

    throw NotImplementedException();
}

ElfFile32::~ElfFile32(){}

SegmentInfo ElfFile32::findSegmentWithName(std::string sectionName){
	UNUSED(sectionName);
	throw NotImplementedException();
}

uint64_t ElfFile32::findAddressOfVariable(std::string symbolName){
	UNUSED(symbolName);
	throw NotImplementedException();
}

ElfFile64::ElfFile64(FILE* fd, size_t fileSize, char* fileContent):
		ElfFile(fd, fileSize, fileContent, ELFTYPE64){

    char *elfEhdr = this->fileContent;
    this->elf64Ehdr = (Elf64_Ehdr *) elfEhdr;
    this->elf64Shdr = (Elf64_Shdr *) (elfEhdr + elf64Ehdr->e_shoff);

	this->shstrindex = elf64Ehdr->e_shstrndx;

	/* find sections SHT_SYMTAB, SHT_STRTAB  */
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		if ((elf64Shdr[i].sh_type == SHT_SYMTAB)) {
			this->symindex = i;
			this->strindex = elf64Shdr[i].sh_link;
		}
	}
	
	uint32_t symSize = elf64Shdr[this->symindex].sh_size;
	Elf64_Sym *symBase = (Elf64_Sym *) (this->fileContent
			+ elf64Shdr[this->symindex].sh_offset);

	for (Elf64_Sym * sym = symBase;
			sym < (Elf64_Sym *) (((char*) symBase) + symSize); sym++) {
		char *currentSymbolName = &((this->fileContent
				+ elf64Shdr[this->strindex].sh_offset)[sym->st_name]);
		symbolNameMap[currentSymbolName] = sym->st_value;
	}
}

ElfFile64::~ElfFile64(){}

SegmentInfo ElfFile64::findSegmentWithName(std::string sectionName){

    char * tempBuf = 0;
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		tempBuf = this->fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset
				+ elf64Shdr[i].sh_name;

		if (sectionName.compare(tempBuf) == 0) {
			return SegmentInfo(sectionName, this->fileContent + elf64Shdr[i].sh_offset,
					elf64Shdr[i].sh_addr, elf64Shdr[i].sh_size);
			//printf("Found Strtab in Section %i: %s\n", i, tempBuf);
		}
	}
	return SegmentInfo();
}

uint64_t ElfFile64::findAddressOfVariable(std::string symbolName){
	return symbolNameMap[symbolName];
}


void ElfFile::printSymbols(){
	char *elfEhdr = this->fileContent;

	if(elfEhdr[4] == ELFCLASS32)
    {
        //TODO
    }
    else if(elfEhdr[4] == ELFCLASS64)
    {
        Elf64_Ehdr * elf64Ehdr;
        Elf64_Shdr * elf64Shdr;

		elf64Ehdr = (Elf64_Ehdr *) elfEhdr;
		elf64Shdr = (Elf64_Shdr *) (elfEhdr + elf64Ehdr->e_shoff);

        uint32_t symSize = elf64Shdr[this->symindex].sh_size;
        Elf64_Sym *symBase = (Elf64_Sym *) (elfEhdr +
									elf64Shdr[this->symindex].sh_offset);

        const char *symbolName;
		const char *sectionName;

		for(Elf64_Sym * sym = symBase;
				sym < (Elf64_Sym *) (((char*) symBase) + symSize) ;
				sym++)
        {
            symbolName = &((elfEhdr +
						elf64Shdr[this->strindex].sh_offset)[sym->st_name]);
			if(sym->st_shndx < SHN_LORESERVE){
				sectionName =  elfEhdr +
						elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
						elf64Shdr[sym->st_shndx].sh_name;
			}else{
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

			if(ELF64_ST_TYPE(sym->st_info) == STT_FUNC ||
					ELF64_ST_TYPE(sym->st_info) == STT_OBJECT){
				printf("Symbol: %016lx %s : %s (%lu)\n",
						sym->st_value, sectionName, symbolName,
						sym->st_size);
			}
        }
    }
}

char* ElfFile::getFileContent(){
	return this->fileContent;
}
ElfLoader* ElfFile32::parseElf(ElfFile::ElfProgramType type){
	if(type == ElfFile::ELFPROGRAMTYPEKERNEL){
		//return new ElfKernelLoader32(this);
	}else if(type == ElfFile::ELFPROGRAMTYPEMODULE){
		//return new ElfModuleLoader32(this);
	}
	return NULL;
}


bool ElfFile32::isRelocatable(){
	assert(false);
	return false;
//	return (elf32Ehdr->e_type == ET_REL);
}

ElfLoader* ElfFile64::parseElf(ElfFile::ElfProgramType type){
	if(type == ElfFile::ELFPROGRAMTYPEKERNEL){
		return new ElfKernelLoader64(this);
	}else if(type == ElfFile::ELFPROGRAMTYPEMODULE){
		//return new ElfModuleLoader64(this);
	}
	return NULL;
}

bool ElfFile64::isRelocatable(){
	return (elf64Ehdr->e_type == ET_REL);
}
