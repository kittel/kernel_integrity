#include "elffile64.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

ElfFile64::ElfFile64(FILE* fd, size_t fileSize, uint8_t* fileContent):
		ElfFile(fd, fileSize, fileContent, ELFTYPE64, ELFPROGRAMTYPEEXEC){ //TODO make this general

    uint8_t *elfEhdr = this->fileContent;
    this->elf64Ehdr = (Elf64_Ehdr *) elfEhdr;
    this->elf64Shdr = (Elf64_Shdr *) (elfEhdr + elf64Ehdr->e_shoff);
	this->elf64Phdr = (Elf64_Phdr *) (elfEhdr + elf64Ehdr->e_phoff);

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
			sym < (Elf64_Sym *) (((uint8_t*) symBase) + symSize); sym++) {
		std::string currentSymbolName = toString(&((this->fileContent
				+ elf64Shdr[this->strindex].sh_offset)[sym->st_name]));
		symbolNameMap[currentSymbolName] = sym->st_value;
	}
}

ElfFile64::~ElfFile64(){}

int ElfFile64::getNrOfSections(){
	return this->elf64Ehdr->e_shnum;
}

/* This function actually searches for a _section_ in the ELF file */
SegmentInfo ElfFile64::findSegmentWithName(std::string sectionName){
	char * tempBuf = 0;
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		tempBuf = (char*) this->fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset
				+ elf64Shdr[i].sh_name;

		if (sectionName.compare(tempBuf) == 0) {
			return SegmentInfo(sectionName, i, 
			                   this->fileContent + 
			                        elf64Shdr[i].sh_offset,
			                        elf64Shdr[i].sh_addr, 
			                   elf64Shdr[i].sh_size);
			//printf("Found Strtab in Section %i: %s\n", i, tempBuf);
		}
	}
	return SegmentInfo();
}

SegmentInfo ElfFile64::findSegmentByID(uint32_t sectionID){
	if(sectionID < elf64Ehdr->e_shnum){

		std::string sectionName = toString(this->fileContent + 
		                      elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + 
		                      elf64Shdr[sectionID].sh_name);
		return SegmentInfo(sectionName, sectionID,
		                   this->fileContent + 
		                        elf64Shdr[sectionID].sh_offset,
		                        elf64Shdr[sectionID].sh_addr, 
		                   elf64Shdr[sectionID].sh_size);
	}
	return SegmentInfo();
}

bool ElfFile64::isCodeAddress(uint64_t address){
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		if (CONTAINS(elf64Shdr[i].sh_addr, elf64Shdr[i].sh_size, address)){
			if( CHECKFLAGS(this->elf64Shdr[i].sh_flags,
						   (SHF_ALLOC & SHF_EXECINSTR))){
				return true;
			}else{
				return false;
			}
		}
	}
	return false;
}

bool ElfFile64::isDataAddress(uint64_t address){
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		if (CONTAINS(elf64Shdr[i].sh_addr, elf64Shdr[i].sh_size, address)){
			if( CHECKFLAGS(this->elf64Shdr[i].sh_flags, (SHF_ALLOC)) &&
				!CHECKFLAGS(this->elf64Shdr[i].sh_flags, (SHF_EXECINSTR))){
				return true;
			}else{
				return false;
			}
		}
	}
	return false;
}

std::string ElfFile64::segmentName(int sectionID){
	return toString(this->fileContent + 
	                   elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + 
	                   elf64Shdr[sectionID].sh_name);
}

uint8_t *ElfFile64::segmentAddress(int sectionID){
	return this->fileContent + this->elf64Shdr[sectionID].sh_offset;
}

uint64_t ElfFile64::segmentAlign(int sectionID){
	return this->elf64Shdr[sectionID].sh_addralign;
}

std::string ElfFile64::symbolName(Elf64_Word index){
	return toString(&((this->fileContent + 
								elf64Shdr[this->strindex].sh_offset)[index]));
}

uint64_t ElfFile64::findAddressOfVariable(std::string symbolName){
	return symbolNameMap[symbolName];
}

bool ElfFile64::isRelocatable(){
	return (elf64Ehdr->e_type == ET_REL);
}

void ElfFile64::applyRelocations(ElfModuleLoader *loader){
	
	if (!this->isRelocatable()){
		return;
	}

	///* loop through every section */
	for(unsigned int i = 0; i < this->elf64Ehdr->e_shnum; i++)
	{
		/* if Elf64_Shdr.sh_addr isn't 0 the section will appear in memory*/
		unsigned int infosec = this->elf64Shdr[i].sh_info;

		/* Not a valid relocation section? */
		if (infosec >= this->elf64Ehdr->e_shnum)
			continue;

		/* Don't bother with non-allocated sections */
		if (!(this->elf64Shdr[infosec].sh_flags & SHF_ALLOC))
			continue;

		//if (this->elf64Shdr[i].sh_type == SHT_REL){
		//	//TODO this is only in the i386 case!
		//	//apply_relocate(fileContent, elf64Shdr, symindex, strindex, i);
		//}
		if (elf64Shdr[i].sh_type == SHT_RELA){
			loader->applyRelocationsOnSection(i);
		}
	}
	return;
}
