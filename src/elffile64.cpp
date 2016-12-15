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
#include "process.h"


namespace kernint {

ElfFile64::ElfFile64(FILE *fd, size_t fileSize, uint8_t *fileContent)
	:
	ElfFile(fd,
	        fileSize,
	        fileContent,
	        ElfType::ELFTYPE64,
	        ElfProgramType::ELFPROGRAMTYPEEXEC) {  // TODO make this general

	uint8_t *elfEhdr = this->fileContent;
	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Ehdr *' increases required alignment from 1 to 8
	this->elf64Ehdr  = (Elf64_Ehdr *)elfEhdr;
	this->elf64Shdr  = (Elf64_Shdr *)(elfEhdr + elf64Ehdr->e_shoff);
	this->elf64Phdr  = (Elf64_Phdr *)(elfEhdr + elf64Ehdr->e_phoff);

	this->shstrindex = elf64Ehdr->e_shstrndx;

	uint32_t symindex = 0;
	uint32_t strindex = 0;

	this->sections.clear();

	// allocate the memory for the section vector
	// so that the data is guaranteed to stay at the same point
	// and pointers and iterators are not invalidated.
	this->sections.reserve(this->getNrOfSections());

	for (unsigned int i = 0; i < this->getNrOfSections(); i++) {
		// find sections SHT_SYMTAB, SHT_STRTAB
		if (elf64Shdr[i].sh_type == SHT_SYMTAB) {
			symindex = i;
			strindex = elf64Shdr[i].sh_link;
		}

		std::string section_name = this->sectionName(i);

		// save section infos
		this->sections.push_back(
			SectionInfo{
				section_name,
				i,
				this->elf64Shdr[i].sh_offset,
				this->fileContent + this->elf64Shdr[i].sh_offset,
				this->elf64Shdr[i].sh_addr,
				this->elf64Shdr[i].sh_size
			}
		);

		SectionInfo *vec_ptr = &(this->sections[i]);
		this->section_ids.insert({i, vec_ptr});
		this->section_names.insert({section_name, vec_ptr});
	}

	// save all segments
	for (int i = 0; i < this->elf64Ehdr->e_phnum; i++) {

		// only store LOAD segments for now.
		if (this->elf64Phdr[i].p_type == PT_LOAD) {
			auto hdr = this->elf64Phdr[i];
			this->segments.push_back(
				SegmentInfo{
					hdr.p_type,
					hdr.p_flags,
					hdr.p_offset,
					hdr.p_vaddr,
					hdr.p_paddr,
					hdr.p_filesz,
					hdr.p_memsz,
					hdr.p_align
				}
			);
		}
	}

	if (!symindex) {
		return;
	}

	uint32_t symSize = elf64Shdr[symindex].sh_size;
	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Sym *' increases required alignment from 1 to 8
	Elf64_Sym *symBase = (Elf64_Sym *)(this->fileContent + elf64Shdr[symindex].sh_offset);

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Sym *' increases required alignment from 1 to 8
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
		if (elf64Shdr[i].sh_type == SHT_SYMTAB) {
			symindex = i;
			strindex = elf64Shdr[i].sh_link;
		}
	}

	if (!symindex) return;

	uint32_t symSize = elf64Shdr[symindex].sh_size;
	Elf64_Sym *symBase = (Elf64_Sym *)(this->fileContent + elf64Shdr[symindex].sh_offset);

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Sym *' increases required alignment from 1 to 8
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
	this->symbols = &(kernel->symbols);
	this->parseDwarf();
	kernel->getParavirtState()->updateState();
	return kernel;
}


ElfModuleLoader *ElfFile64::parseKernelModule(const std::string &name,
                                              Kernel *kernel) {
	auto mod = new ElfModuleLoader64(this, name, kernel);
	this->symbols = &(kernel->symbols);
	mod->initImage();
	this->parseDwarf();
	return mod;
}


ElfUserspaceLoader *ElfFile64::parseUserspace(const std::string &name,
                                              Kernel *kernel,
                                              Process *process) {
	auto proc = new ElfUserspaceLoader64(this, kernel, name);

	this->symbols = &(process->symbols);
	this->parseDwarf();
	return proc;
}


unsigned int ElfFile64::getNrOfSections() const {
	return this->elf64Ehdr->e_shnum;
}


/* This function actually searches for a _section_ in the ELF file */
const SectionInfo &ElfFile64::findSectionWithName(const std::string &sectionName) const {

	auto it = this->section_names.find(sectionName);

	if (it != std::end(this->section_names)) {
		if (it->second->name != sectionName) {
			throw Error{"wrong result in section name map"};
		}

		return *(it->second);
	}

	throw Error{"could not find section by name"};
}


const SectionInfo &ElfFile64::findSectionByID(uint32_t sectionID) const {

	auto it = this->section_ids.find(sectionID);

	if (it != std::end(this->section_ids)) {
		return *(it->second);
	}

	throw Error{"could not find section by id"};
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

bool ElfFile64::isExecutable() const {
	return (this->elf64Ehdr->e_type == ET_EXEC);
}

bool ElfFile64::isDynamicLibrary() const {
	// if this is a static exec we don't have any dependencies
	if (!this->isDynamic() && !this->isExecutable())
		return false;

	// get .dynamic section
	SectionInfo dynamic       = this->findSectionWithName(".dynamic");
	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Dyn *' increases required alignment from 1 to 8
	Elf64_Dyn *dynamicEntries = (Elf64_Dyn *)(dynamic.index);

	for (int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++) {
		if (dynamicEntries[i].d_tag == DT_SONAME) {
			return true;
		}
	}
	return false;
}


void ElfFile64::applyRelocations(ElfLoader *loader,
                                 Kernel *kernel,
                                 Process *process) {

	std::cout << COLOR_GREEN << " == Relocating: "
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

		//std::cout << "# processing relocation " << i << "in "
		//          << relSectionInfo.name << std::endl;

		uint64_t relOffset = rel[i].r_offset;

		// r_offset is the offset from section start
		locInElf = targetSection.index + relOffset;

		// in the guest
		locInMem = targetSection.memindex + relOffset;

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
				uint64_t sectionStart = this->elf64Shdr[j].sh_addr;
				if (sectionStart < relOffset) {
					// if the virtual base address of the section is
					// smaller than the relocation target,
					// it might be the section start
					// try to find the section start that is closest
					// to the relocation target
					if (closest < sectionStart) {
						sectionCandidate = j;
						closest = sectionStart;
					}
				}
			}
			if (sectionCandidate == -1) {
				throw InternalError{"no section can be the target for the relocation"};
			}


			//if (sectionCandidate != symtab[i].st_shndx) {
			//	std::cout << "TODO doesn't match" << std::endl;
			//}

			targetSection = this->findSectionByID(sectionCandidate);
			//std::cout << "relocation will patch section " << targetSection.name << std::endl;

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

		//std::cout << "relocate: r_offset: 0x" << std::hex << relOffset
		//          << std::dec << " -- name: "
		//          << this->symbolName(sym->st_name, strindex)
		//          << std::endl;

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

		//std::cout << "Relocating: "
		//          << this->symbolName(sym->st_name, strindex) << " -> 0x"
		//          << std::hex << sym->st_value << std::dec << std::endl;

		switch (sym->st_shndx) {
		case SHN_COMMON:
			assert(false);
			break;

		case SHN_ABS:
			break;

		case SHN_UNDEF:
			if (is_userspace) {
				// this fetches the value to be written from the process.
				// it can provide all symbol positions, even from
				// libraries it depends on.
				uint64_t addr;

				switch (ELF64_R_TYPE(rel[i].r_info)) {
				case R_X86_64_JUMP_SLOT:
				case R_X86_64_GLOB_DAT: {
					//std::cout << "Need to find address of process symbol: "
					//          << this->symbolName(sym->st_name, strindex)
					//          << std::endl;

					std::string target_symbol = this->symbolName(sym->st_name, strindex);
					addr = process->symbols.getSymbolAddress(target_symbol);

					//std::cout << "addr = " << addr << std::endl;

					if (addr == 0 and not (ELF64_ST_BIND(sym->st_info) == STB_WEAK)) {
						throw Error{"undefined symbol (=0) encountered"};
					}
					sym->st_value = addr;
					break;
				}
				case R_X86_64_RELATIVE:   /* Adjust by program base */
				case R_X86_64_IRELATIVE:  /* Adjust indirectly by program base */
					// TODO:
					std::cout << "TODO: irelative relocation" << std::endl;
					break;

				default:
					throw Error{"unknown relocation type"};
				}
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

			//std::cout << "got/plt relocation at 0x"
			//          << std::hex << reinterpret_cast<uint64_t>(locInElf)
			//          << " to 0x" << val << " off=0x" << sym->st_value
			//          << std::dec << std::endl;

			// TODO: does this get the correct memindex?
			//       the process has to return it
			// write: host-memindex + offset + addend
			*reinterpret_cast<uint64_t *>(locInElf) = val;
			break;

		case R_X86_64_RELATIVE:   /* Adjust by program base */
			// TODO: don't patch JUMP_SLOT if we have lazy binding.
			// instead, write in the _dl_runtime_resolve_{sse,avx,avx512}

			// calculation:
			// RELATIVE: B + A
			// where A = addend, B = base address of shared object

			std::cout << "TODO relative relication at 0x"
			          << std::hex << reinterpret_cast<uint64_t>(locInElf)
			          << " to 0x" << val << " off=0x" << sym->st_value
			          << std::dec << std::endl;

			// maybe: address has to be relative, not absolute

			// write: sectionoffset + addend
			// TODO: add l_addr (aka link map address) here (sectionoffset)
			// val = sym->st_value + addend
			// -> to write: sectionoffset + addend
			// -> write: val - sym->st_value + l_addr
			*reinterpret_cast<uint64_t *>(locInElf) = val - sym->st_value;
			break;

		case R_X86_64_IRELATIVE:  /* Adjust indirectly by program base */

			std::cout << "TODO irelative relication at 0x"
			          << std::hex << reinterpret_cast<uint64_t>(locInElf)
			          << " to 0x" << val << " off=0x" << sym->st_value
			          << std::dec << std::endl;

			// calculation:
			// IRELATIVE: indirect (B + A)
			// where A = addend, B = base address of shared object

			// the value used in this relocation is the program address
			// returned by the func- tion, which takes no arguments, at the
			// address of the result of the corresponding R_X86_64_RELATIVE
			// relocation. One use of the R_X86_64_IRELATIVE relocation is to
			// avoid name lookup for the locally defined STT_GNU_IFUNC symbols
			// at load-time. Support for this relocation is optional, but is
			// required for the STT_GNU_IFUNC symbols

			// TODO!
			*reinterpret_cast<uint64_t *>(locInElf) = val - sym->st_value;

			break;
		case R_X86_64_COPY:
			std::cout << "R_X86_64_COPY relocation, doing nothing!"
			          << std::endl;
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

const SegmentInfo &ElfFile64::findCodeSegment() const {
	for (auto &seg : this->segments) {
		if (seg.type == PT_LOAD) {
			if (seg.flags == (PF_X | PF_R)) {
				return seg;
			}
		}
	}

	throw Error{"could not find code segment"};
}

const SegmentInfo &ElfFile64::findDataSegment() const {
	for (auto &seg : this->segments) {
		if (seg.type == PT_LOAD) {
			if (!CHECKFLAGS(seg.flags, PF_X)) {
				return seg;
			}
		}
	}

	throw Error{"could not find data segment"};
}

const SegmentInfo &ElfFile64::findSegmentByVaddr(const Elf64_Addr addr) const {

	for (auto &seg : this->segments) {
		uint64_t segmentStart = seg.vaddr;
		uint64_t segmentEnd = segmentStart + seg.memsz;
		if (segmentStart <= addr and addr <= segmentEnd) {
			return seg;
		}
	}

	throw Error{"could not find segment by vaddr"};
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


std::vector<ElfSymbol> ElfFile64::getSymbols() const {
	std::vector<ElfSymbol> ret;

	if (not (this->isDynamic() or this->isExecutable())) {
		return ret;
	}

	SectionInfo symtabSection = this->findSectionWithName(".dynsym");
	SectionInfo strtabSection = this->findSectionWithName(".dynstr");

	// TODO: warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'Elf64_Sym *' increases required alignment from 1 to 8
	Elf64_Sym *symtab = (Elf64_Sym *)symtabSection.index;

	char *strtab = (char *)strtabSection.index;

	uint32_t elements = symtabSection.size / sizeof(Elf64_Sym);

	// initialize own symbols
	for (unsigned int i = 0; i < elements; i++) {

		// if symbol is GLOBAL and _not_ UNDEFINED save it for announcement
		if ((ELF64_ST_BIND(symtab[i].st_info) == STB_GLOBAL ||
		     ELF64_ST_BIND(symtab[i].st_info) == STB_WEAK) &&
		    symtab[i].st_shndx != SHN_UNDEF &&
		    symtab[i].st_shndx != SHN_ABS &&
		    symtab[i].st_shndx != SHN_COMMON) {

			// this is final memory address after loading
			uint64_t targetAddr = symtab[i].st_value;

			const SectionInfo *section = &(this->findSectionByID(symtab[i].st_shndx));

			const SegmentInfo *segment = &(this->findSegmentByVaddr(targetAddr));

			ElfSymbol sym{
				std::string{&strtab[symtab[i].st_name]},
				targetAddr,
				symtab[i].st_info,
				symtab[i].st_shndx,
				section,
				segment
			};

			ret.push_back(sym);
		}
	}
	return ret;
}

} // namespace kernint
