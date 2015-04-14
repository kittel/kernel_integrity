#include "elffile32.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

ElfFile32::ElfFile32(FILE* fd, size_t fileSize, uint8_t* fileContent):
	ElfFile(fd, fileSize, fileContent, ELFTYPE32){

    throw NotImplementedException();
}

ElfFile32::~ElfFile32(){}

SegmentInfo ElfFile32::findSegmentWithName(std::string sectionName){
	UNUSED(sectionName);
	throw NotImplementedException();
}

SegmentInfo ElfFile32::findSegmentByID(uint32_t sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

bool ElfFile32::isCodeAddress(uint64_t address){
	UNUSED(address);
	throw NotImplementedException();
}

bool ElfFile32::isDataAddress(uint64_t address){
	UNUSED(address);
	throw NotImplementedException();
}

std::string ElfFile32::segmentName(int sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

uint8_t *ElfFile32::segmentAddress(int sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

void ElfFile32::applyRelocations(ElfModuleLoader *loader){
	UNUSED(loader);
	throw NotImplementedException();
}
		
std::string ElfFile32::symbolName(uint32_t index){
	UNUSED(index);
	throw NotImplementedException();
}

uint64_t ElfFile32::findAddressOfVariable(std::string symbolName){
	UNUSED(symbolName);
	throw NotImplementedException();
}

ElfLoader* ElfFile32::parseElf(ElfFile::ElfProgramType type, 
		                       std::string name,
                               KernelManager* parent){
	UNUSED(name);
	UNUSED(parent);
	if(type == ElfFile::ELFPROGRAMTYPEKERNEL){
		//return new ElfKernelLoader32(this);
	}else if(type == ElfFile::ELFPROGRAMTYPEMODULE){
		//return new ElfModuleLoader32(this, parent);
	}
	return NULL;
}


bool ElfFile32::isRelocatable(){
	assert(false);
	return false;
//	return (elf32Ehdr->e_type == ET_REL);
}
