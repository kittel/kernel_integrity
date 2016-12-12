#include "elfuserspaceloader.h"

#include "kernel.h"
#include "process.h"

namespace kernint {

ElfUserspaceLoader::ElfUserspaceLoader(ElfFile *file,
                                       Kernel *kernel,
                                       const std::string &name)
	:
	ElfLoader(file),
	kernel{kernel},
	name{name},
	baseName{getNameFromPath(name)} {}

ElfUserspaceLoader::~ElfUserspaceLoader() {}

void ElfUserspaceLoader::initText() {
	std::cout << "Initializing text segment for elfuserspaceloader: "
	          << this->name << std::endl;
	this->textSegmentInfo = this->elffile->findCodeSegment();

	auto index = this->elffile->getFileContent() + this->textSegmentInfo.offset;

	// TODO: why pages? the exact size is specified!
	size_t pages = (this->textSegmentInfo.filesz + PAGESIZE) / PAGESIZE;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
	                                index, index + pages * PAGESIZE);

	// TODO: create section info entries.
}

void ElfUserspaceLoader::initData() {
	//std::cout << "Initializing data segment for elfuserspaceloader: "
	//          << this->name << std::endl;

	if(this->getName() == "[vdso]") return;

	// information about the data segment
	this->dataSegmentInfo = this->elffile->findDataSegment();

	if (this->dataSegmentInfo.vaddr == 0) {
		// this elffile does not have a data segment!
		return;
	}

	// create a vector filled with zeroes for the size of the data segment
	auto begin = std::begin(this->dataSegmentContent);

	//std::cout << " reserving segment of size 0x" << std::hex
	//          << this->dataSegmentInfo.memsz
	//          << " with offset 0x" << this->dataSegmentInfo.offset
	//          << std::dec << std::endl;
	this->dataSegmentContent.insert(begin, this->dataSegmentInfo.memsz, 0);

	// copy all sections in the data segment at their correct position
	for (unsigned int i = 0; i < this->elffile->getNrOfSections(); i++) {
		SectionInfo section = this->elffile->findSectionByID(i);

		//std::cout << " trying " << section.name
		//          << " at 0x" << std::hex
		//          << section.offset
		//          << std::dec << std::endl;

		// if this section is within the data segment
		// the section size is subtracted so the start offset check
		// is enough to verify it's in the segment.
		if (CONTAINS(this->dataSegmentInfo.offset,
		             this->dataSegmentInfo.filesz - section.size,
		             section.offset)) {

			//std::cout << " adding section: " << section.name << std::endl;

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


std::vector<ElfUserspaceLoader *> ElfUserspaceLoader::loadDependencies(Process *process) {
	auto dependencies = this->elffile->getDependencies();

	std::vector<ElfUserspaceLoader *> ret;

	for (auto &dep : dependencies) {
		// TODO: the process is needed here because the loading
		//       of the elf requires the right symbol manager,
		//       which is in the process. when the dependencies are loaded,
		//       their mappings are evaluated for the symbol manager,
		//       depending on the process as well.
		ElfLoader *lib = this->kernel->getTaskManager()->loadLibrary(dep, process);
		std::cout << "Loaded library " << lib->getName() << std::endl;

		ElfUserspaceLoader *usLib = dynamic_cast<ElfUserspaceLoader *>(lib);
		if (usLib == nullptr) {
			std::cout << "depended on non-userspace elf" << std::endl;
			assert(0);
		}
		ret.push_back(usLib);
	}

	return ret;
}


/*
 * Initialize a complete memory image for validation.
 * Relocations are not yet processed.
 */
void ElfUserspaceLoader::initImage() {
	// craft text segment
	this->initText();

	// data segment is crafted after the relocations were done
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

const std::string &ElfUserspaceLoader::getBaseName() const {
	return this->baseName;
}


Kernel *ElfUserspaceLoader::getKernel() {
	return this->kernel;
}

std::vector<ElfSymbol> ElfUserspaceLoader::getSymbols() const {
	return this->elffile->getSymbols();
}

} // namespace kernint
