#include "elfprocessloader.h"

#include "process.h"

ElfProcessLoader::ElfProcessLoader(ElfFile *file,
                                   Kernel *kernel,
                                   const std::string &name)
	:
	ElfLoader(file),
	kernel{kernel},
	name{name} {}

ElfProcessLoader::~ElfProcessLoader() {}

void ElfProcessLoader::loadDependencies() {
	auto dependencies = this->elffile->getDependencies();

	for (auto &dep : dependencies) {
		ElfLoader *lib = this->kernel->getTaskManager()->loadLibrary(dep);
		std::cout << "Loaded library " << lib->getName() << std::endl;
	}
}

void ElfProcessLoader::initText() {
	std::cout << "Initializing text segment for elfprocessloader: "
	          << this->name << std::endl;
	this->textSegmentInfo = this->elffile->findCodeSegment();

	auto index = this->elffile->getFileContent() + this->textSegmentInfo.offset;

	// TODO: why pages? the exact size is specified!
	size_t pages = (this->textSegmentInfo.filesz + PAGESIZE) / PAGESIZE;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
	                                index, index + pages * PAGESIZE);
}

void ElfProcessLoader::initData() {
	std::cout << "Initializing data segment for elfprocessloader: "
	          << this->name << std::endl;

	this->dataSegmentInfo = this->elffile->findDataSegment();

	auto index = this->elffile->getFileContent() + this->dataSegmentInfo.offset;
	this->dataSegmentContent.insert(this->dataSegmentContent.end(),
	                                index,
	                                index + this->dataSegmentInfo.filesz);

	// TODO: relocation stuff? lazy bind?
}

/*
 * Initialize a complete memory image for validation. Relocations are not yet
 * processed
 */
void ElfProcessLoader::parse() {
	if (this->elffile->isExecutable()) {
		std::cout << "ElfProcessLoader::parse(): TODO: load VDSO"
		          << std::endl;
		//this->kernel->loadVDSO();

		//create_process
		//store process to kernel
	}

	// Load Dependencies
	this->loadDependencies();
	this->initText();
	this->initData();
}

/* Return the SectionInfo, in which the given addr is contained. */
SectionInfo *ElfProcessLoader::getSegmentForAddress(uint64_t addr) {
	// check textSegment
	if (addr >= (uint64_t) this->textSegment.memindex && addr < ((uint64_t) this->textSegment.memindex) + this->textSegment.size) {
		return &this->textSegment;
	}
	// check dataSection
	else if (addr >= (uint64_t) this->dataSection.memindex && addr < ((uint64_t)(this->dataSection.memindex) + this->dataSection.size)) {
		return &this->dataSection;
	}
	// check heapSection
	else if (addr >= (uint64_t) this->heapSection.memindex &&
	         addr <= (uint64_t)(this->heapSection.memindex + this->heapSection.size)) {
		return &this->heapSection;
	}

	/*
	// check all dependencies TODO
	uint64_t curDepMemindex = dependency.getCurMemindex();
	else if(
	*/
	else {
		return nullptr;
	}
}

void ElfProcessLoader::updateSectionInfoMemAddress(SectionInfo &info) {
	UNUSED(info);
}

/* Check if the given virtual address is located in the textSegment */
bool ElfProcessLoader::isCodeAddress(uint64_t addr) {
	// get offset to last page border
	uint64_t endAddr = ((uint64_t)this->textSegment.memindex)
	                    + (this->textSegmentInfo.offset & 0xfff)
	                    + this->textSegmentInfo.memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if (addr >= ((uint64_t)this->textSegment.memindex)
	    && addr < (endAddr + offset)) {
		return true;
	}
	else {
		return false;
	}
}

/* Check if the given virtual address is located in the dataSection */
bool ElfProcessLoader::isDataAddress(uint64_t addr) {
	UNUSED(addr);
	assert(false);
}

bool ElfProcessLoader::isDataAddress(uint64_t addr, Process *process) {

	auto dataSection = process->getSectionInfoForLib(this->name);
	auto dataSegmentInfo = process->getSegmentInfoForLib(this->name);
	// get offset to last page border
	uint64_t endAddr = ((uint64_t)dataSection->memindex)
	                    + (dataSegmentInfo->offset & 0xfff)
	                    + dataSegmentInfo->memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if (addr >= ((uint64_t)dataSection->memindex)
	    && addr < (endAddr + offset)) {
		return true;
	}
	else {
		return false;
	}
}

/* Check if the given fileOffset (in bytes) lays in the textSegment */
bool ElfProcessLoader::isTextOffset(uint64_t off) {
	return (off >= this->textSegmentInfo.offset &&
	        off <= this->textSegmentInfo.filesz);

}

/* Check if the given fileOffset (in bytes) lays in the dataSection */
bool ElfProcessLoader::isDataOffset(uint64_t off) {
	UNUSED(off);
	assert(false);
}

bool ElfProcessLoader::isDataOffset(uint64_t off, Process *process) {
	auto dataSegmentInfo = process->getSegmentInfoForLib(this->name);
	return (off >= dataSegmentInfo->offset &&
	        off <= dataSegmentInfo->filesz);
}

const std::string &ElfProcessLoader::getName() const {
	return this->name;
}

Kernel *ElfProcessLoader::getKernel() {
	return this->kernel;
}

std::vector<RelSym> ElfProcessLoader::getSymbols() const {
	return this->elffile->getSymbols();
}
