#include "elffile.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

SegmentInfo::SegmentInfo(): segName(), segID(0), index(0), memindex(0), address(0), size(0){}
SegmentInfo::SegmentInfo(uint8_t *i, unsigned int s):
				segName(), segID(), index(i), memindex(0), address(0), size(s){}
SegmentInfo::SegmentInfo(std::string segName, uint32_t segID, uint8_t *i, 
					uint64_t a, uint32_t s):
				segName(segName), segID(segID), index(i), memindex(0),
			   	address(a), size(s){}
SegmentInfo::~SegmentInfo(){}

ElfFile::ElfFile(FILE* fd, size_t fileSize, uint8_t* fileContent, ElfType type):
	shstrindex(0), symindex(0), strindex(0),
	fd(fd), fileSize(fileSize), fileContent(fileContent), type(type),
	filename(""), symbolNameMap(){
	
	try{
		DwarfParser::parseDwarfFromFD(this->getFD());
	}catch(DwarfException &e){
		//std::cout << e.what() << std::endl;
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
	uint8_t* fileContent;

	fd = fopen(filename.c_str(), "rb");
    if (fd != NULL) {
        /* Go to the end of the file. */
        if (fseek(fd, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            fileSize = ftell(fd);

            //MMAP the file to memory
            fileContent = (uint8_t*) mmap(0, fileSize,
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

void ElfFile::printSymbols(){
	uint8_t *elfEhdr = this->fileContent;

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
        Elf64_Sym *symBase = 
		     (Elf64_Sym *) (elfEhdr + elf64Shdr[this->symindex].sh_offset);

		std::string symbolName;
		std::string sectionName;

		for(Elf64_Sym * sym = symBase;
				sym < (Elf64_Sym *) (((char*) symBase) + symSize) ;
				sym++)
        {
            symbolName = this->symbolName(sym->st_name);
			if(sym->st_shndx < SHN_LORESERVE){
				sectionName =  this->segmentName(sym->st_shndx);
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

ElfLoader* ElfFile64::parseElf(ElfFile::ElfProgramType type,
		                       std::string name,
                               KernelManager* parent){
	if(type == ElfFile::ELFPROGRAMTYPEKERNEL){
		return new ElfKernelLoader64(this);
	}else if(type == ElfFile::ELFPROGRAMTYPEMODULE){
		return new ElfModuleLoader64(this, name, parent);
	}
	return NULL;
}


