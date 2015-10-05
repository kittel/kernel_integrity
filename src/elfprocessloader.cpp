#include "elfprocessloader.h"

#define PAGESIZE 0x1000

RelSym::RelSym(std::string name,
	           uint64_t value,
	           uint8_t info,
	           uint32_t shndx,
               ElfProcessLoader* parent):
	name(name), value(value), info(info), shndx(shndx), parent(parent){}

RelSym::~RelSym(){}


ElfProcessLoader::ElfProcessLoader(ElfFile *file, 
		KernelManager *parent,
		std::string name
		):
   	ElfLoader(file, dynamic_cast<ElfKernelLoader*>(parent)->getPVState()),
	execName(name), kernel(parent), textSegmentInfo(), dataSegmentInfo(){
}

ElfProcessLoader::~ElfProcessLoader(){}

void ElfProcessLoader::loadDependencies(){
	auto dependencies = this->elffile->getDependencies();

	for( auto& dep : dependencies){
		kernel->loadLibrary(dep);
	}
}

std::string ElfProcessLoader::getName(){
	return this->execName;
}

void ElfProcessLoader::initText(){}
void ElfProcessLoader::initData(){}

/* Initialize a complete memory image for validation. Relocations are not yet processed */
void ElfProcessLoader::parseElfFile(){

	if(this->elffile->isExecutable()){
		std::cout << "Loading VDSO" << std::endl;
		this->kernel->loadVDSO();
	}
	
	// Load Dependencies
	this->loadDependencies();

	// init the first memory segment
	this->initText();
	// init the second memeory segment
	this->initData();
}

/* Return the beginning of the heap */
uint64_t ElfProcessLoader::getHeapStart(){

	// heap starts after last data page
	// if size not page aligned
	uint16_t offset = 0;
	if((this->dataSection.size % 0x1000) != 0x0){
		offset = PAGESIZE - ((uint64_t)this->dataSection.size & 0xfff);
	}

	uint64_t heapStart = (uint64_t)this->dataSection.memindex
							+ this->dataSection.size
							+ offset;
	return heapStart;
}

/* Return a reference to the loader inheriting the given addr */
ElfProcessLoader* ElfProcessLoader::getExecForAddress(uint64_t addr){

	if((addr >= (uint64_t) this->textSegment.memindex &&
	    addr < (uint64_t) (this->textSegment.memindex +
	                       this->textSegment.size)) ||
	   (addr >= (uint64_t) this->dataSection.memindex &&
	    addr < (uint64_t) (this->dataSection.memindex +
	                       this->dataSection.size))){
		return this; 
	}

	//TODO search through dependencies.
	return NULL;
}

/* Return the SectionInfo, in which the given addr is contained. */
SectionInfo* ElfProcessLoader::getSegmentForAddress(uint64_t addr){

	// check textSegment
	if(addr >= (uint64_t) this->textSegment.memindex &&
		addr < ((uint64_t)this->textSegment.memindex) +
		                  this->textSegment.size){
		return &this->textSegment;
	}
	// check dataSection
	else if(addr >= (uint64_t)this->dataSection.memindex &&
			addr < ((uint64_t)(this->dataSection.memindex) +
			                   this->dataSection.size)){
		return &this->dataSection;
	}
	// check heapSection
	else if(addr >= (uint64_t)this->heapSection.memindex &&
			addr <= (uint64_t)(this->heapSection.memindex +
			                   this->heapSection.size)){
		return &this->heapSection;
	}

/*
	// check all dependencies TODO
	uint64_t curDepMemindex = dependency.getCurMemindex();
	else if(
*/
	else{
		return NULL;
	}
}

void ElfProcessLoader::updateSectionInfoMemAddress(SectionInfo &info){
	UNUSED(info);
}
void ElfProcessLoader::addSymbols(){}
