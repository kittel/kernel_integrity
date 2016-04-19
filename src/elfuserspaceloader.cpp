#include "elfuserspaceloader.h"

#include "kernel.h"
#include "process.h"

ElfUserspaceLoader::ElfUserspaceLoader(ElfFile *file,
                                   Kernel *kernel,
                                   const std::string &name)
	:
	ElfLoader(file),
	kernel{kernel},
	name{name} {}

ElfUserspaceLoader::~ElfUserspaceLoader() {}

void ElfUserspaceLoader::loadDependencies() {
	auto dependencies = this->elffile->getDependencies();

	for (auto &dep : dependencies) {
		ElfLoader *lib = this->kernel->getTaskManager()->loadLibrary(dep);
		std::cout << "Loaded library " << lib->getName() << std::endl;
	}
}

void ElfUserspaceLoader::initText() {
	std::cout << "Initializing text segment for elfuserspaceloader: "
	          << this->name << std::endl;
	this->textSegmentInfo = this->elffile->findCodeSegment();

	auto index = this->elffile->getFileContent() + this->textSegmentInfo.offset;

	// TODO: why pages? the exact size is specified!
	size_t pages = (this->textSegmentInfo.filesz + PAGESIZE) / PAGESIZE;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
	                                index, index + pages * PAGESIZE);
}

void ElfUserspaceLoader::initData() {
	std::cout << "Initializing data segment for elfuserspaceloader: "
	          << this->name << std::endl;

	// information about the data segment
	this->dataSegmentInfo = this->elffile->findDataSegment();

	// create a vector filled with zeroes for the size of the data segment
	auto begin = std::begin(this->dataSegmentContent);

	std::cout << " reserving segment of size 0x" << std::hex
	          << this->dataSegmentInfo.memsz
	          << " with offset 0x" << this->dataSegmentInfo.offset
	          << std::dec << std::endl;
	this->dataSegmentContent.insert(begin, this->dataSegmentInfo.memsz, 0);

	// copy all sections in the data segment at their correct position
	for (unsigned int i = 0; i < this->elffile->getNrOfSections(); i++) {
		SectionInfo section = this->elffile->findSectionByID(i);

		std::cout << " trying " << section.name
		          << " at 0x" << std::hex
		          << section.offset
		          << std::dec << std::endl;

		// if this section is within the data segment
		// the section size is subtracted so the start offset check
		// is enough to verify it's in the segment.
		if (CONTAINS(this->dataSegmentInfo.offset,
		             this->dataSegmentInfo.filesz - section.size,
		             section.offset)) {

			std::cout << " adding section: " << section.name << std::endl;

			uint8_t *data = (this->elffile->getFileContent() +
			                 section.offset);

			// TODO: vaddr or paddr?
			auto position = (std::begin(this->dataSegmentContent) +
			                 section.memindex - this->dataSegmentInfo.vaddr);

			this->dataSegmentContent.insert(
				position,
				data,
				data + section.size
			);
		}
	}
}

/*
 * Initialize a complete memory image for validation. Relocations are not yet
 * processed
 */
void ElfUserspaceLoader::parse() {
	if (this->elffile->isExecutable()) {
		std::cout << "ElfUserspaceLoader::parse(): TODO: load VDSO"
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
SectionInfo *ElfUserspaceLoader::getSegmentForAddress(uint64_t addr) {
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

void ElfUserspaceLoader::updateSectionInfoMemAddress(SectionInfo &info) {
	UNUSED(info);
}

/* Check if the given virtual address is located in the textSegment */
bool ElfUserspaceLoader::isCodeAddress(uint64_t addr) {
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
bool ElfUserspaceLoader::isDataAddress(uint64_t addr) {
	UNUSED(addr);
	assert(false);
}

bool ElfUserspaceLoader::isDataAddress(uint64_t addr, Process *process) {

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
bool ElfUserspaceLoader::isTextOffset(uint64_t off) {
	return (off >= this->textSegmentInfo.offset &&
	        off <= this->textSegmentInfo.filesz);

}

/* Check if the given fileOffset (in bytes) lays in the dataSection */
bool ElfUserspaceLoader::isDataOffset(uint64_t off) {
	UNUSED(off);
	assert(false);
}

bool ElfUserspaceLoader::isDataOffset(uint64_t off, Process *process) {
	auto dataSegmentInfo = process->getSegmentInfoForLib(this->name);
	return (off >= dataSegmentInfo->offset &&
	        off <= dataSegmentInfo->filesz);
}

const std::string &ElfUserspaceLoader::getName() const {
	return this->name;
}

Kernel *ElfUserspaceLoader::getKernel() {
	return this->kernel;
}

std::vector<RelSym> ElfUserspaceLoader::getSymbols() const {
	return this->elffile->getSymbols();
}
