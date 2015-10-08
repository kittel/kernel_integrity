#include "elffile32.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

ElfFile32::ElfFile32(FILE* fd, size_t fileSize, uint8_t* fileContent)
	:
	ElfFile(fd, fileSize, fileContent, ElfType::ELFTYPE32, ElfProgramType::ELFPROGRAMTYPEMODULE) {

	throw NotImplementedException();
}

ElfFile32::~ElfFile32(){}

int ElfFile32::getNrOfSections(){
	throw NotImplementedException();
}

SectionInfo ElfFile32::findSectionWithName(std::string sectionName){
	UNUSED(sectionName);
	throw NotImplementedException();
}

SectionInfo ElfFile32::findSectionByID(uint32_t sectionID){
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

std::string ElfFile32::sectionName(int sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

uint8_t *ElfFile32::sectionAddress(int sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

uint64_t ElfFile32::sectionAlign(int sectionID){
	UNUSED(sectionID);
	throw NotImplementedException();
}

SegmentInfo ElfFile32::findCodeSegment(){
	throw NotImplementedException();
}

SegmentInfo ElfFile32::findDataSegment(){
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

ElfLoader *ElfFile32::parseElf(ElfProgramType type,
                               std::string name,
                               KernelManager *parent){
	UNUSED(name);
	UNUSED(parent);
	if (type == ElfProgramType::ELFPROGRAMTYPEKERNEL) {
		//return new ElfKernelLoader32(this);
	} else if(type == ElfProgramType::ELFPROGRAMTYPEMODULE) {
		//return new ElfModuleLoader32(this, parent);
	}
	return nullptr;
}


bool ElfFile32::isRelocatable(){
	assert(false);
	throw NotImplementedException();
	return false;
//	return (elf32Ehdr->e_type == ET_REL);
}

bool ElfFile32::isDynamic(){
	assert(false);
	throw NotImplementedException();
	return false;
}

bool ElfFile32::isExecutable(){
	assert(false);
	throw NotImplementedException();
	return false;
}
std::vector<std::string> ElfFile32::getDependencies(){
	assert(false);
	throw NotImplementedException();
}

