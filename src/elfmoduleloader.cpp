#include "elfmoduleloader.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfModuleLoader::ElfModuleLoader(ElfFile *elffile,
                                 const std::string &name,
                                 Kernel *kernel)
	:
	ElfLoader(elffile),
	modName(name),
	kernel(kernel),
	pvpatcher(kernel->getParavirtState()) {}

ElfModuleLoader::~ElfModuleLoader() {}

const std::string &ElfModuleLoader::getName() const {
	return this->modName;
}

Kernel *ElfModuleLoader::getKernel() {
	return this->kernel;
}

void ElfModuleLoader::loadDependencies(void) {
	SectionInfo miS = this->elffile->findSectionWithName(".modinfo");

	// parse .modinfo and load dependencies
	char *modinfo = (char *)miS.index;
	char *module  = nullptr;
	char *saveptr;
	if (!modinfo) {
		return;
	}

	while (modinfo < (char *)(miS.index) + miS.size) {
		// std::cout << "Searching for string" << std::endl;
		// check if the string starts with depends
		if (modinfo[0] == 0) {
			modinfo++;
			continue;
		} else if (strncmp(modinfo, "depends", 7) != 0) {
			modinfo += strlen(modinfo) + 1;
			continue;
		} else {
			// string.compare(0, 7, "depends")
			modinfo += 8;

			module = strtok_r(modinfo, ",", &saveptr);
			while (module != nullptr) {
				if (*module == 0) {
					break;
				}
				kernel->loadModule(module);
				module = strtok_r(nullptr, ",", &saveptr);
			}
			return;
		}
	}
}

void ElfModuleLoader::initText(void) {
	// std::cout << COLOR_GREEN
	//             "Loading dependencies for module " << this->modName;
	// std::cout << COLOR_NORM << std::endl;

	this->loadDependencies();

	std::cout << COLOR_GREEN "Loading module " << this->modName;
	std::cout << COLOR_NORM << std::endl;

	this->elffile->applyRelocations(this, kernel);

	this->textSegment = this->elffile->findSectionWithName(".text");
	this->updateSectionInfoMemAddress(this->textSegment);

	// applyJumpEntries();

	// perform patching
	this->applyAltinstr(&this->pvpatcher);
	this->pvpatcher.applyParainstr(this);
	this->applySmpLocks();

	// Content of text section in memory:
	// same as the sections in the elf binary

	this->textSegmentContent.clear();
	this->textSegmentContent.insert(this->textSegmentContent.end(),
	                                this->textSegment.index,
	                                this->textSegment.index
	                                + this->textSegment.size);

	uint8_t *fileContent  = this->elffile->getFileContent();
	Elf64_Ehdr *elf64Ehdr = (Elf64_Ehdr *)fileContent;
	Elf64_Shdr *elf64Shdr = (Elf64_Shdr *)(fileContent + elf64Ehdr->e_shoff);
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		std::string sectionName = this->elffile->sectionName(i);
		if (sectionName.compare(".text") == 0 ||
		    sectionName.compare(".init.text") == 0) {
			continue;
		}

		if (elf64Shdr[i].sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
			this->textSegmentContent.insert(
			    this->textSegmentContent.end(),
			    fileContent + elf64Shdr[i].sh_offset,
			    fileContent + elf64Shdr[i].sh_offset + elf64Shdr[i].sh_size);
		}
	}

	// Fill up the last page
	uint32_t fill = 0x1000 - (this->textSegmentContent.size() % 0x1000);
	this->textSegmentContent.insert(this->textSegmentContent.end(), fill, 0);

	SectionInfo info = this->elffile->findSectionWithName("__mcount_loc");
	this->updateSectionInfoMemAddress(info);
	this->applyMcount(info, &this->pvpatcher);

	// Initialize the symTable in the context for later reference
	this->elffile->addSymbolsToKernel(this->kernel,
	                                  (uint64_t)this->textSegment.memindex);
}

void ElfModuleLoader::initData(void) {
	this->dataSection = this->elffile->findSectionWithName(".data");
	this->updateSectionInfoMemAddress(this->dataSection);
	this->bssSection = elffile->findSectionWithName(".bss");
	this->updateSectionInfoMemAddress(this->bssSection);
	this->roDataSection = elffile->findSectionWithName(".note.gnu.build-id");
	this->updateSectionInfoMemAddress(this->roDataSection);

	// initialize roData Segment
	ElfFile64 *elf64      = dynamic_cast<ElfFile64 *>(this->elffile);
	Elf64_Shdr *elf64Shdr = elf64->elf64Shdr;
	for (unsigned int i = 0; i < elf64->elf64Ehdr->e_shnum; i++) {
		if (((elf64Shdr[i].sh_flags == SHF_ALLOC ||
		      elf64Shdr[i].sh_flags == SHF_STRINGS) &&
		     elf64Shdr[i].sh_type == SHT_PROGBITS) ||
		    (elf64Shdr[i].sh_flags == SHF_ALLOC &&
		     elf64Shdr[i].sh_type == SHT_NOTE)) {
			std::string sectionName = this->elffile->sectionName(i);
			if (sectionName.compare(".modinfo") == 0 ||
			    sectionName.compare("__versions") == 0 ||
			    sectionName.substr(0, 5).compare(".init") == 0)
				continue;
			uint64_t align         = (elf64Shdr[i].sh_addralign ?: 1) - 1;
			uint64_t alignmentSize = (this->roData.size() + align) & ~align;
			this->roData.insert(
			    this->roData.end(), alignmentSize - this->roData.size(), 0);
			this->roData.insert(
			    this->roData.end(),
			    this->elffile->getFileContent() + elf64Shdr[i].sh_offset,
			    this->elffile->getFileContent() + elf64Shdr[i].sh_offset +
			        elf64Shdr[i].sh_size);
		}
	}
	this->roDataSection.size = this->roData.size();
}

uint8_t *ElfModuleLoader::findMemAddressOfSegment(SectionInfo &info) {
	std::string segName = info.segName;
	Instance module;
	Instance currentModule = this->kernel->getKernelModuleInstance(this->modName);

	// If the searching for the .bss section
	// This section is right after the modules struct
	if (segName.compare(".bss") == 0) {
		uint64_t align = this->elffile->sectionAlign(info.segID);

		uint64_t offset = currentModule.size() % align;
		(offset == 0) ? offset = currentModule.size()
		              : offset = currentModule.size() + align - offset;

		return (uint8_t *)currentModule.getAddress() + offset;
	}

	if (segName.compare("__ksymtab_gpl") == 0) {
		return (uint8_t *)currentModule.memberByName("gpl_syms").getRawValue<uint64_t>();
	}

	// Find the address of the current section in the memory image
	// Get Number of sections in kernel image
	Instance attrs    = currentModule.memberByName("sect_attrs", true);
	uint32_t attr_cnt = attrs.memberByName("nsections").getValue<uint64_t>();

	// Now compare all section names until we find the correct section.
	for (uint j = 0; j < attr_cnt; ++j) {
		Instance attr = attrs.memberByName("attrs").arrayElem(j);
		std::string sectionName = attr.memberByName("name", true).getValue<std::string>();
		if (sectionName.compare(segName) == 0) {
			return (uint8_t *)attr.memberByName("address").getValue<uint64_t>();
		}
	}
	return 0;
}

/* Update the target virtual address of the segment */
void ElfModuleLoader::updateSectionInfoMemAddress(SectionInfo &info) {
	info.memindex = this->findMemAddressOfSegment(info);
}

bool ElfModuleLoader::isDataAddress(uint64_t addr) {
	addr = addr | 0xffff000000000000;
	return (this->dataSection.containsMemAddress(addr) ||
	        this->bssSection.containsMemAddress(addr));
}
