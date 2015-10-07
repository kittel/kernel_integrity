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

ElfLoader* ElfFile64::parseElf(ElfFile::ElfProgramType type,
		                       std::string name,
                               KernelManager* parent){
	if(type == ElfFile::ELFPROGRAMTYPEKERNEL){
		return new ElfKernelLoader64(this);
	}else if(type == ElfFile::ELFPROGRAMTYPEMODULE){
		return new ElfModuleLoader64(this,
				name, parent);
	}else if(type == ElfFile::ELFPROGRAMTYPEEXEC){
		return new ElfProcessLoader64(this,
				parent, name);
		//TODO: name doesn't get handled properly
	}
	std::cout << "No usable ELFPROGRAMTYPE defined." << std::endl;
	return nullptr;
}

int ElfFile64::getNrOfSections(){
	return this->elf64Ehdr->e_shnum;
}

/* This function actually searches for a _section_ in the ELF file */
SectionInfo ElfFile64::findSectionWithName(std::string sectionName){
	char * tempBuf = 0;
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		tempBuf = (char*) this->fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset
				+ elf64Shdr[i].sh_name;

		if (sectionName.compare(tempBuf) == 0) {
			return SectionInfo(sectionName, i,
			                   this->fileContent +
			                        elf64Shdr[i].sh_offset,
			                        elf64Shdr[i].sh_addr,
			                   elf64Shdr[i].sh_size);
			//printf("Found Strtab in Section %i: %s\n", i, tempBuf);
		}
	}
	return SectionInfo();
}

SectionInfo ElfFile64::findSectionByID(uint32_t sectionID){
	if(sectionID < elf64Ehdr->e_shnum){

		std::string sectionName = toString(this->fileContent +
		                      elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
		                      elf64Shdr[sectionID].sh_name);
		return SectionInfo(sectionName, sectionID,
		                   this->fileContent +
		                        elf64Shdr[sectionID].sh_offset,
		                        elf64Shdr[sectionID].sh_addr,
		                   elf64Shdr[sectionID].sh_size);
	}
	return SectionInfo();
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

std::string ElfFile64::sectionName(int sectionID){
	return toString(this->fileContent +
	                   elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
	                   elf64Shdr[sectionID].sh_name);
}

uint8_t *ElfFile64::sectionAddress(int sectionID){
	return this->fileContent + this->elf64Shdr[sectionID].sh_offset;
}

uint64_t ElfFile64::sectionAlign(int sectionID){
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

bool ElfFile64::isDynamic(){
	return (elf64Ehdr->e_type == ET_DYN);
}

bool ElfFile64::isExecutable(){
	return (elf64Ehdr->e_type == ET_EXEC);
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

std::vector<std::string> ElfFile64::getDependencies(){
	std::vector<std::string> dependencies;

	// if this is a static exec we don't have any dependencies
	if(!this->isDynamic() && !this->isExecutable()) return dependencies;

	// get .dynamic section
	SectionInfo dynamic = this->findSectionWithName(".dynamic");
	SectionInfo dynstr = this->findSectionWithName(".dynstr");
	Elf64_Dyn *dynamicEntries = (Elf64_Dyn*)(dynamic.index);
	char *strtab = (char*)(dynstr.index);

	for(int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++){
		if(dynamicEntries[i].d_tag == DT_NEEDED){
			// insert name from symbol table on which the d_val is pointing
			dependencies.push_back(
			        std::string(&strtab[(dynamicEntries[i].d_un.d_val)]));
		}
		//if(dynamicEntries[i].d_tag == DT_BIND_NOW){
		//	this->bindLazy = false;
		//}
	}
	return dependencies;
}

SegmentInfo ElfFile64::findCodeSegment(){
	for(int i = 0; i < this->elf64Ehdr->e_phnum; i++){
		if(this->elf64Phdr[i].p_type == PT_LOAD){
			if(this->elf64Phdr[i].p_flags == (PF_X | PF_R)){
				auto hdr = this->elf64Phdr[i];
				return SegmentInfo(hdr.p_type, hdr.p_flags, hdr.p_offset,
				         (uint8_t*) hdr.p_vaddr, (uint8_t*) hdr.p_paddr,
				         hdr.p_filesz, hdr.p_memsz, hdr.p_align);
			}
		}
	}
	return SegmentInfo();
}

SegmentInfo ElfFile64::findDataSegment(){
	for(int i = 0; i < this->elf64Ehdr->e_phnum; i++){
		if(this->elf64Phdr[i].p_type == PT_LOAD){
			if(!CHECKFLAGS(this->elf64Phdr[i].p_flags, PF_X)){
				auto hdr = this->elf64Phdr[i];
				return SegmentInfo(hdr.p_type, hdr.p_flags, hdr.p_offset,
				         (uint8_t*) hdr.p_vaddr, (uint8_t*) hdr.p_paddr,
				         hdr.p_filesz, hdr.p_memsz, hdr.p_align);
			}
		}
	}
	return SegmentInfo();
}

template<typename T>
void ElfFile64::getRelEntries(std::vector<T> &ret, uint32_t type){
	int maxSec = this->getNrOfSections();
	int nrRel = 0;

	// find .rel sections
	for(int i = 0; i < maxSec; i++){
		if(this->elf64Shdr[i].sh_type == type){

			nrRel = (int)(this->elf64Shdr[i].sh_size / sizeof(T));
			auto index = this->fileContent + elf64Shdr[i].sh_offset;

			// add .rel entries to vector
			for(int j = 0; j < nrRel; j++){
				ret.push_back(((T*) index)[j]);
			}
		}
	}
}

/* Return all relocation entries from all .rel sections
 *
 *  - find .rel sections (if any)
 *  - build vector from entries
 */
void ElfFile64::getRelEntries(std::vector<Elf64_Rel> &ret){
	this->getRelEntries(ret, SHT_REL);
}

/* Return all relocation entries from all .rela sections
 *
 *  - find .rela sections (if any)
 *  - build vector from entries
 */
void ElfFile64::getRelaEntries(std::vector<Elf64_Rela> &ret){
	this->getRelEntries(ret, SHT_RELA);
}
