#include "elffile64.h"

#include <cstdio>
#include <cassert>

#include "elfloader.h"
#include "elfkernelloader64.h"
#include "elfmoduleloader64.h"
#include "elfuserspaceloader64.h"
#include "error.h"
#include "helpers.h"
#include "kernel.h"
#include "libdwarfparser/libdwarfparser.h"
#include "libvmiwrapper/libvmiwrapper.h"


namespace kernint {

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
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
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

		if (!sym->st_name) {
			continue;
		}

		std::string symbolName = this->symbolName(sym->st_name, strindex);
		uint64_t symbolAddress = sym->st_value;

		this->symbolNameMap[symbolName] = symbolAddress;
	}
}

ElfFile64::~ElfFile64() {}

// memindex: base address of the module elf file .text section
void ElfFile64::addSymbolsToStore(SymbolManager *store, uint64_t memindex) const {
	uint32_t symindex = 0;
	uint32_t strindex = 0;

	/* find sections SHT_SYMTAB, SHT_STRTAB  */
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
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

		store->addSymbolAddress(symbolName, symbolAddress);

		// We also have to consider local functions
		// if((ELF64_ST_TYPE(sym->st_info) & STT_FUNC) &&
		// ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
		if ((ELF64_ST_TYPE(sym->st_info) == STT_FUNC)) {
			if (symbolAddress < memindex) {
				symbolAddress += memindex;
			}
			store->addFunctionAddress(symbolName, symbolAddress);
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
	mod->initImage();
	this->parseDwarf();
	return mod;
}

ElfUserspaceLoader *ElfFile64::parseUserspace(const std::string &name,
                                              Kernel *kernel) {
	auto proc = new ElfUserspaceLoader64(this, kernel, name);

	this->parseDwarf();
	// TODO: transfer symbols from loader this->symbols
	return proc;
}

unsigned int ElfFile64::getNrOfSections() const {
	return this->elf64Ehdr->e_shnum;
}

/* This function actually searches for a _section_ in the ELF file */
SectionInfo ElfFile64::findSectionWithName(const std::string &sectionName) const {
	char *tempBuf = nullptr;
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
		tempBuf = (char *)this->fileContent +
		          this->elf64Shdr[this->elf64Ehdr->e_shstrndx].sh_offset +
		          this->elf64Shdr[i].sh_name;

		if (sectionName.compare(tempBuf) == 0) {
			return SectionInfo(
				sectionName,
				i,
				this->elf64Shdr[i].sh_offset,
				this->fileContent + this->elf64Shdr[i].sh_offset,
				this->elf64Shdr[i].sh_addr,
				this->elf64Shdr[i].sh_size
			);
		}
	}
	assert(0);
}

SectionInfo ElfFile64::findSectionByID(uint32_t sectionID) const {
	if (sectionID < this->getNrOfSections()) {
		auto dataptr = this->fileContent + this->elf64Shdr[sectionID].sh_offset;

		// TODO: really `infosec`? not just sectionID?
		unsigned int infosec = this->elf64Shdr[sectionID].sh_info;
		if (infosec < this->getNrOfSections()) {
			if (this->elf64Shdr[infosec].sh_type == SHT_NOBITS) {
				if (this->elf64Shdr[infosec].sh_flags & SHF_ALLOC) {
					// TODO: create vector
					std::cout << "TODO: alloc NOBITS section: "
					          << this->sectionName(sectionID)
					          << std::endl;
					throw InternalError("NOBITS implementation");
				}
			}
		}

		return SectionInfo(
			this->sectionName(sectionID),
			sectionID,
			this->elf64Shdr[sectionID].sh_offset,
			dataptr,
			this->elf64Shdr[sectionID].sh_addr,
			this->elf64Shdr[sectionID].sh_size
		);
	}
	assert(0);
}

bool ElfFile64::isCodeAddress(uint64_t address) {
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
		if (CONTAINS(this->elf64Shdr[i].sh_addr,
		             this->elf64Shdr[i].sh_size, address)) {
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
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
		if (CONTAINS(this->elf64Shdr[i].sh_addr,
		             this->elf64Shdr[i].sh_size, address)) {
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

std::string ElfFile64::sectionName(int sectionID) const {
	return toString(this->fileContent +
	                this->elf64Shdr[this->elf64Ehdr->e_shstrndx].sh_offset +
	                this->elf64Shdr[sectionID].sh_name);
}

uint8_t *ElfFile64::sectionAddress(int sectionID) {
	return this->fileContent + this->elf64Shdr[sectionID].sh_offset;
}

uint64_t ElfFile64::sectionAlign(int sectionID) {
	return this->elf64Shdr[sectionID].sh_addralign;
}

std::string ElfFile64::symbolName(Elf64_Word index, uint32_t strindex) const {
	return toString(&((this->fileContent + this->elf64Shdr[strindex].sh_offset)[index]));
}

uint64_t ElfFile64::findAddressOfVariable(const std::string &symbolName) {
	return this->symbolNameMap[symbolName];
}

bool ElfFile64::isRelocatable() const {
	return (this->elf64Ehdr->e_type == ET_REL);
}

bool ElfFile64::isDynamic() const {
	return (this->elf64Ehdr->e_type == ET_DYN);
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
	return (this->elf64Ehdr->e_type == ET_EXEC);
}


void ElfFile64::applyRelocations(ElfLoader *loader,
                                 Kernel *kernel,
                                 Process *process) {

	std::cout << COLOR_GREEN << "Relocating: "
	          << this->filename << COLOR_NORM
	          << std::endl;

	switch(this->elf64Ehdr->e_type) {
	case ET_REL:
	case ET_DYN:
	case ET_EXEC:
		for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
			unsigned int infosec = this->elf64Shdr[i].sh_info;
			if (infosec >= this->getNrOfSections())
				continue;

			/* Don't bother with non-allocated sections */
			if (!(this->elf64Shdr[infosec].sh_flags & SHF_ALLOC))
				continue;

			if (this->elf64Shdr[i].sh_type == SHT_REL) {
				std::cout << "wtf? REL relocations are not used, "
				             "instead expecting RELA!" << std::endl;
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
                                   ElfLoader *loader,
                                   Kernel *kernel,
                                   Process *process) {

	// TODO: this is wrong! somehow it's a different section!
	Elf32_Word sectionID    = this->elf64Shdr[relSectionID].sh_info;

	Elf32_Word symindex     = this->elf64Shdr[relSectionID].sh_link;
	Elf32_Word strindex     = this->elf64Shdr[symindex].sh_link;
	assert(symindex);

	std::string sectionName = this->sectionName(sectionID);
	bool isAltinstrSection = false;
	if (sectionName.compare(".altinstructions") == 0) {
		isAltinstrSection = true;
	}

	// TODO: use inheritance or callbacks to differentiate
	//       between elf file types instead of totally clobbering
	//       this function with special cases.
	bool is_userspace = process != nullptr;

	// the section where to apply the relocations to
	SectionInfo targetSection = this->findSectionByID(sectionID);

	// TODO: what does this do??
	loader->updateSectionInfoMemAddress(targetSection);

	SectionInfo relSectionInfo = this->findSectionByID(relSectionID);

	Elf64_Rela *rel = reinterpret_cast<Elf64_Rela *>(relSectionInfo.index);
	Elf64_Sym *symBase = reinterpret_cast<Elf64_Sym *>(this->sectionAddress(symindex));

	// TODO move this to a dedicated function if used with kernel modules
	//      a userspace process doesn't have this section.
	// loader->pre_relocation_hook()...
	SectionInfo percpuDataSection;

	if (not is_userspace) {
		percpuDataSection = this->findSectionWithName(".data..percpu");
	}

	// static member within the for loop
	SectionInfo symRelSectionInfo;

	for (uint32_t i = 0; i < relSectionInfo.size / sizeof(*rel); i++) {
		uint8_t *locInElf = nullptr;      // on host
		uint64_t locInMem = 0;            // on guest
		size_t locOfRelSectionInElf = 0;  // on host
		size_t locOfRelSectionInMem = 0;  // on guest

		// r_offset is the offset from section start
		locInElf = targetSection.index + rel[i].r_offset;

		// in the guest
		locInMem = targetSection.memindex + rel[i].r_offset;

		switch (this->elf64Ehdr->e_type) {
		case ET_EXEC:
		case ET_DYN: {
			// r_offset is the virtual address of the patch position

			// TODO: this is ultra-dirty!
			//       we are trying to find the section where
			//       the relocation should be applied to
			//       by looking which section start address
			//       is the closest one.
			int sectionCandidate = -1;
			Elf64_Addr closest = 0;
			for (unsigned int j = 0; j < this->getNrOfSections(); j++) {
				if (this->elf64Shdr[j].sh_addr < rel[i].r_offset) {
					// if the virtual base address of the section is
					// smaller than the relocation target,
					// it might be the section start
					// try to find the section start that is closest
					// to the relocation target
					if (closest < this->elf64Shdr[j].sh_addr) {
						sectionCandidate = j;
						closest = this->elf64Shdr[j].sh_addr;
					}
				}
			}
			if (sectionCandidate == -1) {
				throw InternalError{"no section can be the target for the relocation"};
			}


			targetSection = this->findSectionByID(sectionCandidate);
			std::cout << "relocation will patch section " << targetSection.name << std::endl;

			// remove the base address of the section
			// so we can operate on the mapped file address later:
			//         (r_offset - virtual segment start)
			// (to eliminate the virtual address)
			locInElf -= targetSection.memindex;

			break;
		}
		case ET_REL:
		default:
			break;
		}

		Elf64_Sym *sym = symBase + ELF64_R_SYM(rel[i].r_info);

		std::cout << "relocate: r_offset: 0x" << std::hex << rel[i].r_offset
		          << std::dec << " -- name: "
		          << this->symbolName(sym->st_name, strindex)
		          << std::endl;

		if (symRelSectionInfo.secID != sym->st_shndx) {
			symRelSectionInfo = this->findSectionByID(sym->st_shndx);
			loader->updateSectionInfoMemAddress(symRelSectionInfo);
		}

		// TODO: move to dedicated function as unusable
		//       for userspace processes
		// loader->relocation_hook(sym->st_shndx)
		if (not is_userspace) {
			if (sym->st_shndx == percpuDataSection.secID) {
				Instance currentModule = loader->getKernel()->getKernelModuleInstance(loader->getName());
				symRelSectionInfo.memindex = currentModule.memberByName("percpu").getRawValue<uint64_t>(false);
			}
		}

		// store section starts for host and guest
		locOfRelSectionInElf = reinterpret_cast<size_t>(symRelSectionInfo.index);
		locOfRelSectionInMem = reinterpret_cast<size_t>(symRelSectionInfo.memindex);

		std::cout << "Relocating: "
		          << this->symbolName(sym->st_name, strindex) << " -> 0x"
		          << std::hex << sym->st_value << std::dec << std::endl;

		switch (sym->st_shndx) {
		case SHN_COMMON:
			assert(false);
			break;
		case SHN_ABS:
			break;
		case SHN_UNDEF:
			if (is_userspace) {
				std::cout << "Need to find address of process symbol: "
				          << this->symbolName(sym->st_name, strindex)
				          << std::endl;

				// this fetches the value to be written from the process.
				// it can provide all symbol positions, even from
				// libraries it depends on.
				sym->st_value = process->symbols.getSymbolAddress(
					this->symbolName(sym->st_name, strindex));
			}
			else {
				sym->st_value = kernel->symbols.getSymbolAddress(
					this->symbolName(sym->st_name, strindex));
			}
			break;
		default:
			// sometimes, in the kernel one only gets the offset in the section
			if (sym->st_value < locOfRelSectionInMem) {
				sym->st_value += locOfRelSectionInMem;
			}
			break;
		}

		// now follows the actual relocation part.
		// this is what we'll write:
		uint64_t val = sym->st_value + rel[i].r_addend;

		// depending on the relocation type, write differently:
		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE:
			break;

		case R_X86_64_64:
			*reinterpret_cast<uint64_t *>(locInElf) = val;
			break;

		case R_X86_64_32:
			*reinterpret_cast<uint64_t *>(locInElf) = val;
			break;

		case R_X86_64_32S:
			*reinterpret_cast<uint32_t *>(locInElf) = val;
			break;

		case R_X86_64_PC32:
			if (isAltinstrSection) {
				// This is later used to copy some memory
				val = val -
				      reinterpret_cast<uint64_t>(locOfRelSectionInMem) +
				      reinterpret_cast<uint64_t>(locOfRelSectionInElf) -
				      reinterpret_cast<uint64_t>(locInElf);
			} else {
				// make it relative again
				val -= locInMem;
			}

			*reinterpret_cast<uint32_t *>(locInElf) = val;
			break;

		case R_X86_64_GLOB_DAT:   /* Create GOT entry */
		case R_X86_64_JUMP_SLOT:  /* Create PLT entry */

			std::cout << "got/plt relocation at 0x"
			          << std::hex << reinterpret_cast<uint64_t>(locInElf)
			          << " to 0x" << val << " off=0x" << sym->st_value
			          << std::dec << std::endl;

			// TODO: does this get the correct memindex?
			//       the process has to return it
			// write: host-memindex + offset + addend
			*reinterpret_cast<uint64_t *>(locInElf) = val;
			break;

		case R_X86_64_RELATIVE:   /* Adjust by program base */
		case R_X86_64_IRELATIVE:  /* Adjust indirectly by program base */
			// TODO: don't patch JUMP_SLOT if we have lazy binding.
			// instead, write in the _dl_runtime_resolve_{sse,avx,avx512}

			std::cout << "(i)relative relication at 0x"
			          << std::hex << reinterpret_cast<uint64_t>(locInElf)
			          << " to 0x" << val << " off=0x" << sym->st_value
			          << std::dec << std::endl;

			// maybe: address has to be relative, not absolute

			// write: sectionoffset + addend
			*reinterpret_cast<uint64_t *>(locInElf) = val - sym->st_value;
			break;

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
	Elf64_Dyn *dynamicEntries = reinterpret_cast<Elf64_Dyn *>(dynamic.index);
	char *strtab              = reinterpret_cast<char *>(dynstr.index);

	for (int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++) {
		if (dynamicEntries[i].d_tag == DT_NEEDED) {
			// insert name from symbol table on which the d_val is pointing
			dependencies.push_back(
				std::string(&strtab[dynamicEntries[i].d_un.d_val]));
		}

		/*
		// TODO: lazy binding!
		if (dynamicEntries[i].d_tag == DT_BIND_NOW) {
			this->doLazyBind = false;
		}
		*/
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
				                   hdr.p_vaddr,
				                   hdr.p_paddr,
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
				                   hdr.p_vaddr,
				                   hdr.p_paddr,
				                   hdr.p_filesz,
				                   hdr.p_memsz,
				                   hdr.p_align);
			}
		}
	}
	return SegmentInfo();
}

template <typename T>
std::vector<T> ElfFile64::getRelocationEntries(uint32_t type) const {
	std::vector<T> ret;

	// find .rel sections
	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
		// check the relocation type
		if (this->elf64Shdr[i].sh_type == type) {
			int nrRel = (int)(this->elf64Shdr[i].sh_size / sizeof(T));
			auto index = this->fileContent + elf64Shdr[i].sh_offset;

			// add .rel entries to vector
			for (int j = 0; j < nrRel; j++) {
				ret.push_back((reinterpret_cast<T *>(index))[j]);
			}
		}
	}

	return ret;
}

// Return all relocation entries from all .rel sections
std::vector<Elf64_Rel> ElfFile64::getRelEntries() const {
	return this->getRelocationEntries<Elf64_Rel>(SHT_REL);
}

// Return all relocation entries from all .rela sections
std::vector<Elf64_Rela> ElfFile64::getRelaEntries() const {
	return this->getRelocationEntries<Elf64_Rela>(SHT_RELA);
}


std::vector<RelSym> ElfFile64::getSymbols() const {
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

			// TODO: implement getVAForAddr!!!!!!
			targetAddr = 0;
			// targetAddr = this->getVAForAddr(symtab[i].st_value,
			//                                 symtab[i].st_shndx);

			RelSym sym = RelSym(std::string{&strtab[symtab[i].st_name]},
			                    targetAddr,
			                    symtab[i].st_info,
			                    symtab[i].st_shndx);

			ret.push_back(sym);
		}
	}
	return ret;
}

} // namespace kernint
