#include "elfprocessloader.h"


ElfProcessLoader::ElfProcessLoader(ElfFile *file, std::string name)
                                   : ElfLoader(file), execName(name){
//	std::cout << "ElfProcessLoader initialized with name " << name << std::endl;
}

ElfProcessLoader::~ElfProcessLoader(){
}

std::string ElfProcessLoader::getName(){
	return this->execName;
}

uint64_t ElfProcessLoader::getHeapStart(){
	return 0x0;
}

ElfLoader* ElfProcessLoader::getExecForAddress(uint64_t address){
	std::cout << std::hex << (void*)address << std::endl;
	return NULL;
}

SegmentInfo* ElfProcessLoader::getSegmentForAddress(uint64_t addr){
	std::cout << std::hex << (void*)addr << std::endl;
	return NULL;
}

uint8_t* ElfProcessLoader::getImageForAddress(uint64_t addr, uint32_t offset){
	std::cout << std::hex << (void*)addr << "||" << offset << std::endl;
	return NULL;
}

void ElfProcessLoader::printImage(){}
uint64_t ElfProcessLoader::getStartAddr(){return 0xf;}
void ElfProcessLoader::initText(){}
void ElfProcessLoader::initData(){}
void ElfProcessLoader::addSymbols(){}
bool ElfProcessLoader::isDataAddress(uint64_t addr){
	std::cout << std::hex << addr << std::endl;
	return true;
}

void ElfProcessLoader::supplyVDSO(ElfProcessLoader *vdso){
	assert(vdso);
}

void ElfProcessLoader::supplyLibraries(std::vector<ElfProcessLoader*> *libs){
	assert(libs);
}


uint8_t* ElfProcessLoader::findMemAddressOfSegment(std::string segName){
	uint8_t *ret;
	ret = NULL;
	std::cout << segName << std::endl;
	return ret;
}
void ElfProcessLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	std::cout << std::hex << &info << std::endl;
}

