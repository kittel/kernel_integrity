#include "elffile64.h"

#include "exceptions.h"
#include "elfloader.h"

#include "helpers.h"

#include <stdio.h>
#include <cassert>

#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"

ElfFile64::ElfFile64(FILE *fd, size_t fileSize, uint8_t *fileContent)
	:
	ElfFile(fd,
	        fileSize,
	        fileContent,
	        ElfType::ELFTYPE64,
	        ElfProgramType::ELFPROGRAMTYPEEXEC) {  // TODO make this general

	uint8_t *elfEhdr = this->fileContent;
	this->elf64Ehdr  = (Elf64_Ehdr *)elfEhdr;
	this->elf64Shdr  = (Elf64_Shdr *)(elfEhdr + elf64Ehdr->e_shoff);
	this->elf64Phdr  = (Elf64_Phdr *)(elfEhdr + elf64Ehdr->e_phoff);

	this->shstrindex = elf64Ehdr->e_shstrndx;

	uint32_t symindex = 0;
	uint32_t strindex = 0;

	/* find sections SHT_SYMTAB, SHT_STRTAB  */
	for (unsigned int i = 0; i < this->elf64Ehdr->e_shnum; i++) {
		if ((elf64Shdr[i].sh_type == SHT_SYMTAB )) {
			symindex = i;
			strindex = elf64Shdr[i].sh_link;
		}
	}

	if (!symindex) return;

	uint32_t symSize = elf64Shdr[symindex].sh_size;
	Elf64_Sym *symBase = (Elf64_Sym *)(this->fileContent + elf64Shdr[symindex].sh_offset);

	for (Elf64_Sym *sym = symBase;
	     sym < (Elf64_Sym *)(((uint8_t *)symBase) + symSize);
	     sym++) {
		if(!sym->st_name) continue;

		std::string symbolName = this->symbolName(sym->st_name, strindex);
		uint64_t symbolAddress = sym->st_value;

		symbolNameMap[symbolName] = symbolAddress;
	}
}

ElfFile64::~ElfFile64() {}

void ElfFile64::addSymbolsToKernel(Kernel *kernel, uint64_t memindex) const {
	uint32_t symindex = 0;
	uint32_t strindex = 0;

	/* find sections SHT_SYMTAB, SHT_STRTAB  */
	for (unsigned int i = 0; i < this->elf64Ehdr->e_shnum; i++) {
		if ((elf64Shdr[i].sh_type == SHT_SYMTAB )) {
			symindex = i;
			strindex = elf64Shdr[i].sh_link;
		}
	}

	if (!symindex) return;

	uint32_t symSize = elf64Shdr[symindex].sh_size;
	Elf64_Sym *symBase = (Elf64_Sym *)(this->fileContent + elf64Shdr[symindex].sh_offset);

	for (Elf64_Sym *sym = symBase;
	     sym < (Elf64_Sym *)(((uint8_t *)symBase) + symSize);
	     sym++) {
		if(!sym->st_name) continue;

		std::string symbolName = this->symbolName(sym->st_name, strindex);
		uint64_t symbolAddress = sym->st_value;

		if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
			// Store local variables with uniq names
			symbolName.append("@@").append("kernel");
			std::string newSymName = symbolName;
			symbolName = newSymName;
		}
		kernel->addSymbolAddress(symbolName, symbolAddress);

		// We also have to consider local functions
		// if((ELF64_ST_TYPE(sym->st_info) & STT_FUNC) &&
		// ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
		if ((ELF64_ST_TYPE(sym->st_info) == STT_FUNC)) {
			if (symbolAddress < memindex) symbolAddress += memindex;
			kernel->addFunctionAddress(symbolName, symbolAddress);
		}
	}

}

ElfKernelLoader *ElfFile64::parseKernel() {
	auto kernel = new ElfKernelLoader64(this);
	this->symbols = &kernel->symbols;
	this->parseDwarf();
	kernel->getParavirtState()->updateState();
	return kernel;
}

ElfModuleLoader *ElfFile64::parseKernelModule(const std::string &name,
                                              Kernel *kernel) {
	auto mod = new ElfModuleLoader64(this, name, kernel);
	assert(kernel);
	this->symbols = &kernel->symbols;
	mod->parse();
	this->parseDwarf();
	return mod;
}

ElfProcessLoader *ElfFile64::parseProcess(const std::string &name,
                                          Process *process,
                                          Kernel *kernel) {
	auto proc = new ElfProcessLoader64(this, kernel, name, process);
	this->symbols = &process->symbols;
	this->parseDwarf();
	return proc;
}

int ElfFile64::getNrOfSections() {
	return this->elf64Ehdr->e_shnum;
}

/* This function actually searches for a _section_ in the ELF file */
SectionInfo ElfFile64::findSectionWithName(const std::string &sectionName) const {
	char *tempBuf = 0;
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		tempBuf = (char *)this->fileContent +
		          elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
		          elf64Shdr[i].sh_name;

		if (sectionName.compare(tempBuf) == 0) {
			return SectionInfo(sectionName,
			                   i,
			                   this->fileContent + elf64Shdr[i].sh_offset,
			                   elf64Shdr[i].sh_addr,
			                   elf64Shdr[i].sh_size);
			// printf("Found Strtab in Section %i: %s\n", i, tempBuf);
		}
	}
	return SectionInfo();
}

SectionInfo ElfFile64::findSectionByID(uint32_t sectionID) const {
	if (sectionID < elf64Ehdr->e_shnum) {
		std::string sectionName = toString(
		    this->fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
		    elf64Shdr[sectionID].sh_name);
		return SectionInfo(sectionName,
		                   sectionID,
		                   this->fileContent + elf64Shdr[sectionID].sh_offset,
		                   elf64Shdr[sectionID].sh_addr,
		                   elf64Shdr[sectionID].sh_size);
	}
	return SectionInfo();
}

bool ElfFile64::isCodeAddress(uint64_t address) {
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		if (CONTAINS(elf64Shdr[i].sh_addr, elf64Shdr[i].sh_size, address)) {
			if (CHECKFLAGS(this->elf64Shdr[i].sh_flags,
			               (SHF_ALLOC & SHF_EXECINSTR))) {
				return true;
			} else {
				return false;
			}
		}
	}
	return false;
}

bool ElfFile64::isDataAddress(uint64_t address) {
	for (unsigned int i = 0; i < elf64Ehdr->e_shnum; i++) {
		if (CONTAINS(elf64Shdr[i].sh_addr, elf64Shdr[i].sh_size, address)) {
			if (CHECKFLAGS(this->elf64Shdr[i].sh_flags, (SHF_ALLOC)) &&
			    !CHECKFLAGS(this->elf64Shdr[i].sh_flags, (SHF_EXECINSTR))) {
				return true;
			} else {
				return false;
			}
		}
	}
	return false;
}

std::string ElfFile64::sectionName(int sectionID) {
	return toString(this->fileContent +
	                elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset +
	                elf64Shdr[sectionID].sh_name);
}

uint8_t *ElfFile64::sectionAddress(int sectionID) {
	return this->fileContent + this->elf64Shdr[sectionID].sh_offset;
}

uint64_t ElfFile64::sectionAlign(int sectionID) {
	return this->elf64Shdr[sectionID].sh_addralign;
}

std::string ElfFile64::symbolName(Elf64_Word index, uint32_t strindex) const {
	return toString(&((this->fileContent + elf64Shdr[strindex].sh_offset)[index]));
}

uint64_t ElfFile64::findAddressOfVariable(const std::string &symbolName) {
	return symbolNameMap[symbolName];
}

bool ElfFile64::isRelocatable() const {
	return (elf64Ehdr->e_type == ET_REL);
}

bool ElfFile64::isDynamic() const {
	return (elf64Ehdr->e_type == ET_DYN);
}

bool ElfFile64::isDynamicLibrary() const {
	// if this is a static exec we don't have any dependencies
	if (!this->isDynamic() && !this->isExecutable())
		return false;

	// get .dynamic section
	SectionInfo dynamic       = this->findSectionWithName(".dynamic");
	Elf64_Dyn *dynamicEntries = (Elf64_Dyn *)(dynamic.index);

	for (int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++) {
		if (dynamicEntries[i].d_tag == DT_SONAME) {
			return true;
		}
	}
	return false;
}

bool ElfFile64::isExecutable() const {
	return (elf64Ehdr->e_type == ET_EXEC);
}

void ElfFile64::applyRelocations(ElfLoader *loader,
                                 Kernel *kernel,
                                 Process *process) {
	switch(elf64Ehdr->e_type) {
	case ET_REL:
	case ET_DYN:
		for (unsigned int i = 0; i < this->elf64Ehdr->e_shnum; i++) {
			unsigned int infosec = this->elf64Shdr[i].sh_info;
			if (infosec >= this->elf64Ehdr->e_shnum)
				continue;

			/* Don't bother with non-allocated sections */
			if (!(this->elf64Shdr[infosec].sh_flags & SHF_ALLOC))
				continue;

			if (this->elf64Shdr[i].sh_type == SHT_REL){
				assert(false);
			}
			if (this->elf64Shdr[i].sh_type == SHT_RELA) {
				this->applyRelaOnSection(i, loader, kernel, process);
			}
		}
		break;
	default:
		std::cout << "Not relocatable: " << this->getFilename() << std::endl;
	}
}

void ElfFile64::applyRelaOnSection(uint32_t relSectionID,
                                   ElfLoader* loader,
                                   Kernel *kernel,
                                   Process *process) {

	Elf32_Word sectionID    = this->elf64Shdr[relSectionID].sh_info;
	Elf32_Word symindex     = this->elf64Shdr[relSectionID].sh_link;
	Elf32_Word strindex     = this->elf64Shdr[symindex].sh_link;

	std::string sectionName = this->sectionName(sectionID);
	bool isAltinstrSection = false;
	if (sectionName.compare(".altinstructions") == 0) {
		isAltinstrSection = true;
	}

	SectionInfo sectionInfo = this->findSectionByID(sectionID);
	loader->updateSectionInfoMemAddress(sectionInfo);

	SectionInfo relSectionInfo = this->findSectionByID(relSectionID);

	Elf64_Rela *rel = (Elf64_Rela *)relSectionInfo.index;
	assert(symindex);
	Elf64_Sym *symBase = (Elf64_Sym *)this->sectionAddress(symindex);

	// TODO move this to a dedicated function if used with kernel modules
	SectionInfo percpuDataSegment = this->findSectionWithName(".data..percpu");

	// static member within the for loop
	SectionInfo symRelSectionInfo;

	for (uint32_t i = 0; i < relSectionInfo.size / sizeof(*rel); i++) {
		void *locInElf             = 0;
		void *locInMem             = 0;
		void *locOfRelSectionInMem = 0;
		void *locOfRelSectionInElf = 0;

		/* This is where to make the change */
		locInElf = (void *)((char *)sectionInfo.index + rel[i].r_offset);
		locInMem = (void *)((char *)sectionInfo.memindex + rel[i].r_offset);

		Elf64_Sym *sym = symBase + ELF64_R_SYM(rel[i].r_info);

		if (symRelSectionInfo.segID != sym->st_shndx) {
			symRelSectionInfo =
			    this->findSectionByID(sym->st_shndx);
			loader->updateSectionInfoMemAddress(symRelSectionInfo);
		}

		if(sym->st_shndx == percpuDataSegment.segID) {
			Instance currentModule = loader->getKernel()->
			                getKernelModuleInstance(loader->getName());
			symRelSectionInfo.memindex =
			    (uint8_t *) currentModule.memberByName("percpu")
			                          .getRawValue<uint64_t>(false);
		}

		switch (sym->st_shndx) {
		case SHN_COMMON:
			assert(false);
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
			if (process) {
				std::cout << "Need to find address of symbol: " <<
				this->symbolName(sym->st_name, strindex) << std::endl;
			//	sym->st_value = process->findAddressOfSymbol(
			//	                            this->symbolName(sym->st_name));
			} else {
				sym->st_value = kernel->findAddressOfSymbol(
				                    this->symbolName(sym->st_name, strindex));
			}
			break;
		default:
			locOfRelSectionInElf = (void *)symRelSectionInfo.index;
			locOfRelSectionInMem = (void *)symRelSectionInfo.memindex;

			if (sym->st_value < (long unsigned int)locOfRelSectionInMem) {
				sym->st_value += (long unsigned int)locOfRelSectionInMem;
			}
			break;
		}

		if(process) return;

		uint64_t val = sym->st_value + rel[i].r_addend;

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE: break;
		case R_X86_64_64: *(uint64_t *)locInElf = val; break;
		case R_X86_64_32:
			*(uint64_t *)locInElf = val;
			assert(val == *(uint64_t *)locInElf);
			break;
		case R_X86_64_32S:
			*(uint32_t *)locInElf = val;
			assert(val == (uint64_t) *(int32_t *)locInElf);
			break;
		case R_X86_64_PC32:
			if (isAltinstrSection) {
				// This is later used to copy some memory
				val = val - (uint64_t)locOfRelSectionInMem +
				      (uint64_t)locOfRelSectionInElf - (uint64_t)locInElf;
			} else {
				val -= (uint64_t)locInMem;
			}
			*(uint32_t *)locInElf = val;
			break;
		case R_X86_64_GLOB_DAT:   /* Create GOT entry */
		case R_X86_64_JUMP_SLOT:  /* Create PLT entry */
		case R_X86_64_RELATIVE:   /* Adjust by program base */
		case R_X86_64_IRELATIVE:  /* Adjust indirectly by program base */
			*(uint64_t *)locInElf = val; break;
		default:
			std::cout << COLOR_RED << "Unknown RELA: "
			          << "Requested Type: " << ELF64_R_TYPE(rel[i].r_info)
			          << COLOR_NORM << std::endl;
			assert(false);
			return;
		}
	}
	return;
}

std::vector<std::string> ElfFile64::getDependencies() {
	std::vector<std::string> dependencies;

	// if this is a static exec we don't have any dependencies
	if (!this->isDynamic() && !this->isExecutable())
		return dependencies;

	// get .dynamic section
	SectionInfo dynamic       = this->findSectionWithName(".dynamic");
	SectionInfo dynstr        = this->findSectionWithName(".dynstr");
	Elf64_Dyn *dynamicEntries = (Elf64_Dyn *)(dynamic.index);
	char *strtab              = (char *)(dynstr.index);

	for (int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++) {
		if (dynamicEntries[i].d_tag == DT_NEEDED) {
			// insert name from symbol table on which the d_val is pointing
			dependencies.push_back(
			    std::string(&strtab[(dynamicEntries[i].d_un.d_val)]));
		}
		// if(dynamicEntries[i].d_tag == DT_BIND_NOW){
		//	this->bindLazy = false;
		//}
	}
	return dependencies;
}

SegmentInfo ElfFile64::findCodeSegment() {
	for (int i = 0; i < this->elf64Ehdr->e_phnum; i++) {
		if (this->elf64Phdr[i].p_type == PT_LOAD) {
			if (this->elf64Phdr[i].p_flags == (PF_X | PF_R)) {
				auto hdr = this->elf64Phdr[i];
				return SegmentInfo(hdr.p_type,
				                   hdr.p_flags,
				                   hdr.p_offset,
				                   (uint8_t *)hdr.p_vaddr,
				                   (uint8_t *)hdr.p_paddr,
				                   hdr.p_filesz,
				                   hdr.p_memsz,
				                   hdr.p_align);
			}
		}
	}
	return SegmentInfo();
}

SegmentInfo ElfFile64::findDataSegment() {
	for (int i = 0; i < this->elf64Ehdr->e_phnum; i++) {
		if (this->elf64Phdr[i].p_type == PT_LOAD) {
			if (!CHECKFLAGS(this->elf64Phdr[i].p_flags, PF_X)) {
				auto hdr = this->elf64Phdr[i];
				return SegmentInfo(hdr.p_type,
				                   hdr.p_flags,
				                   hdr.p_offset,
				                   (uint8_t *)hdr.p_vaddr,
				                   (uint8_t *)hdr.p_paddr,
				                   hdr.p_filesz,
				                   hdr.p_memsz,
				                   hdr.p_align);
			}
		}
	}
	return SegmentInfo();
}

template <typename T>
void ElfFile64::getRelEntries(std::vector<T> &ret, uint32_t type) {
	int maxSec = this->getNrOfSections();
	int nrRel  = 0;

	// find .rel sections
	for (int i = 0; i < maxSec; i++) {
		if (this->elf64Shdr[i].sh_type == type) {
			nrRel      = (int)(this->elf64Shdr[i].sh_size / sizeof(T));
			auto index = this->fileContent + elf64Shdr[i].sh_offset;

			// add .rel entries to vector
			for (int j = 0; j < nrRel; j++) {
				ret.push_back(((T *)index)[j]);
			}
		}
	}
}

/* Return all relocation entries from all .rel sections
 *
 *  - find .rel sections (if any)
 *  - build vector from entries
 */
void ElfFile64::getRelEntries(std::vector<Elf64_Rel> &ret) {
	this->getRelEntries(ret, SHT_REL);
}

/* Return all relocation entries from all .rela sections
 *
 *  - find .rela sections (if any)
 *  - build vector from entries
 */
void ElfFile64::getRelaEntries(std::vector<Elf64_Rela> &ret) {
	this->getRelEntries(ret, SHT_RELA);
}


std::vector<RelSym> ElfFile64::getSymbols() {
	std::vector<RelSym> ret;

	if (!this->isDynamic()) {
		return ret;
	}

	SectionInfo symtabSection = this->findSectionWithName(".dynsym");
	SectionInfo strtabSection = this->findSectionWithName(".dynstr");

	Elf64_Sym *symtab = (Elf64_Sym *)symtabSection.index;

	char *strtab = (char *)strtabSection.index;

	uint64_t targetAddr = 0;  // this is final memory address after loading

	uint32_t elements = symtabSection.size / sizeof(Elf64_Sym);
	// initialize own symbols

	for (unsigned int i = 0; i < elements; i++) {
		// if symbol is GLOBAL and _not_ UNDEFINED save it for announcement
		if ((ELF64_ST_BIND(symtab[i].st_info) == STB_GLOBAL ||
		     ELF64_ST_BIND(symtab[i].st_info) == STB_WEAK) &&
		    symtab[i].st_shndx != SHN_UNDEF &&
		    symtab[i].st_shndx != SHN_ABS &&
		    symtab[i].st_shndx != SHN_COMMON) {

			// TODO
			targetAddr = 0;
			// targetAddr = this->getVAForAddr(symtab[i].st_value,
			//                                 symtab[i].st_shndx);

			RelSym sym = RelSym(std::string(&strtab[symtab[i].st_name]),
			                    targetAddr,
			                    symtab[i].st_info,
			                    symtab[i].st_shndx);

			ret.push_back(sym);
		}
	}
	return ret;
}
