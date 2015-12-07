#include "elfmoduleloader64.h"

#include "helpers.h"

#include "exceptions.h"

//#define PRINTDEBUG

ElfModuleLoader64::ElfModuleLoader64(ElfFile64 *elffile,
                                     const std::string &name,
                                     Kernel *kernel)
	:
	ElfModuleLoader(elffile, name, kernel) {

	this->parse();
}

ElfModuleLoader64::~ElfModuleLoader64() {}

void ElfModuleLoader64::applyRelocationsOnSection(uint32_t relSectionID) {
	ElfFile64 *elf = dynamic_cast<ElfFile64 *>(this->elffile);
	assert(elf);

	SectionInfo relSectionInfo = this->elffile->findSectionByID(relSectionID);

	Elf32_Word sectionID    = elf->elf64Shdr[relSectionID].sh_info;
	std::string sectionName = this->elffile->sectionName(sectionID);

	SectionInfo sectionInfo = this->elffile->findSectionByID(sectionID);
	this->updateSectionInfoMemAddress(sectionInfo);
	Elf64_Rela *rel = (Elf64_Rela *)relSectionInfo.index;

	Elf64_Sym *symBase = (Elf64_Sym *)this->elffile->sectionAddress(this->elffile->symindex);

	SectionInfo percpuDataSegment = this->elffile->findSectionWithName(".data..percpu");
	Instance currentModule = this->kernel->getKernelModuleInstance(this->modName);

#ifdef PRINTDEBUG
	bool doPrint = false;
	if (this->getName().compare("nfs") == 0 &&
	    sectionName.compare(".text") == 0) {
		doPrint = true;
	}
	// if(doPrint) std::cout << "\n\nSection To Relocate: " << sectionName <<
	// std::endl;
#endif

	SectionInfo symRelSectionInfo;

	for (uint32_t i = 0; i < relSectionInfo.size / sizeof(*rel); i++) {
		void *locInElf             = 0;
		void *locInMem             = 0;
		void *locOfRelSectionInMem = 0;
		void *locOfRelSectionInElf = 0;

		/* This is where to make the change */
		locInElf = (void *)((char *)sectionInfo.index + rel[i].r_offset);
		locInMem = (void *)((char *)sectionInfo.memindex + rel[i].r_offset);

		Elf64_Sym *sym = 0;
		sym            = symBase + ELF64_R_SYM(rel[i].r_info);

#ifdef PRINTDEBUG
		if (this->getName().compare("snd_pcm") == 0
		    //&& sectionName.compare(".text") == 0
		    &&
		    rel[i].r_offset == 0x3d55)
			doPrint = true;

		if (doPrint)
			std::cout << "\n\nSymbol: "
			          << this->elffile->symbolName(sym->st_name) << std::endl;
		if (doPrint)
			std::cout << "Relocation: " << i << std::endl;
		if (doPrint)
			std::cout << "locInElf = " << std::hex << (uint64_t)locInElf
			          << std::dec << std::endl;
		if (doPrint)
			std::cout << "locInMem = " << std::hex << (uint64_t)locInMem
			          << std::dec << std::endl;
		if (doPrint)
			std::cout << "offset = " << std::hex << (uint64_t)rel[i].r_offset
			          << std::dec << std::endl;
#endif

		switch (sym->st_shndx) {
		case SHN_COMMON:

#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "Symtype SHN_UNDEF" << std::endl;
			std::cout << "This should not happen!" << std::endl;
#endif
			assert(false);
			continue;  // TODO REMOVE
			break;
		case SHN_ABS:
#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "Symtype SHN_ABS" << std::endl;
#endif
			break;
		case SHN_UNDEF:
#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "Symtype SHN_UNDEF" << std::endl;
#endif
			sym->st_value =
			    this->relocateShnUndef(this->elffile->symbolName(sym->st_name));
#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "Found Symbol at " << std::hex << sym->st_value
				          << std::dec << std::endl;
#endif
			break;
		default:
#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "default: " << std::endl;
// debugerr("Sym Type: default: " << sym->st_shndx);
#endif

			// TODO this is not right yet.
			/* Divert to percpu allocation if a percpu var. */
			if (sym->st_shndx == percpuDataSegment.segID) {
				locOfRelSectionInMem =
				    (void *)currentModule.memberByName("percpu")
				        .getRawValue<uint64_t>(false);
				std::cout << "relocation @ " << std::hex << locOfRelSectionInMem
				          << std::dec << std::endl;
			} else {
				if (symRelSectionInfo.segID != sym->st_shndx) {
					symRelSectionInfo =
					    this->elffile->findSectionByID(sym->st_shndx);
					this->updateSectionInfoMemAddress(symRelSectionInfo);
				}
				locOfRelSectionInElf = (void *)symRelSectionInfo.index;
				locOfRelSectionInMem = (void *)symRelSectionInfo.memindex;
			}

			if (sym->st_value < (long unsigned int)locOfRelSectionInMem) {
				sym->st_value += (long unsigned int)locOfRelSectionInMem;
			}
			break;
		}

		uint64_t val = sym->st_value + rel[i].r_addend;

#ifdef PRINTDEBUG
		if (doPrint)
			std::cout << "raddend: " << std::hex << rel[i].r_addend << std::dec
			          << std::endl;
		if (doPrint)
			std::cout << "sym->value: " << std::hex << sym->st_value << std::dec
			          << std::endl;
		if (doPrint)
			std::cout << "val: " << std::hex << val << std::dec << std::endl;
#endif

		switch (ELF64_R_TYPE(rel[i].r_info)) {
		case R_X86_64_NONE: break;
		case R_X86_64_64: *(uint64_t *)locInElf = val; break;
		case R_X86_64_32:
			*(uint64_t *)locInElf = val;
			if (val != *(uint64_t *)locInElf) {
				assert(false);
				return;
				// goto overflow;
			}
			break;
		case R_X86_64_32S:
			*(uint32_t *)locInElf = val;
			if (val != (uint64_t) * (int32_t *)locInElf) {
				assert(false);
				return;
				// goto overflow;
			}
			break;
		case R_X86_64_PC32:

			// This line is from the original source the loc here is the
			//  location within the loaded module.

			// val -= (u64)loc;
			if (sectionName.compare(".altinstructions") == 0) {
				// This is later used to copy some memory
				val = val - (uint64_t)locOfRelSectionInMem +
				      (uint64_t)locOfRelSectionInElf - (uint64_t)locInElf;
			} else {
				// This is used as relocation in memory
				val -= (uint64_t)locInMem;
			}
#ifdef PRINTDEBUG
			if (doPrint)
				std::cout << "PC32 final value: " << std::hex << (uint32_t)val
				          << std::dec << std::endl;
#endif
			*(uint32_t *)locInElf = val;
#if 0
			if ((int64_t)val != *(int32_t *)loc)
				assert(false);
			return;
			//goto overflow;
#endif
			break;
		default:
#ifdef PRINTDEBUG
			std::cout << "Unknown rela relocation: "
			          << ELF64_R_TYPE(rel[i].r_info) << std::endl;
#endif
			assert(false);
			return;
		}
#ifdef PRINTDEBUG
		doPrint = false;
#endif
	}
	return;
}

uint64_t ElfModuleLoader64::relocateShnUndef(const std::string &symbolName) {
	// First look into the system map.
	// As we depend on dwarf anyway we use that information to find
	// a variable.

	uint64_t address = this->kernel->getSystemMapAddress(symbolName);
	if (address != 0) {
		return address;
	}
	address = this->kernel->getSymbolAddress(symbolName);
	if (address != 0) {
		return address;
	}
	address = this->kernel->getFunctionAddress(symbolName);
	if (address != 0) {
		return address;
	}

	// Variable not found in system.map
	// Try to find the variable by name in insight.
	Function *func = this->elffile->symbols->findFunctionByName(symbolName);
	if (func && func->getAddress()) {
		return func->getAddress();
	}

	Variable *var = this->elffile->symbols->findVariableByName(symbolName);
	if (var && var->getLocation()) {
		return var->getLocation();
	}
	std::cout << COLOR_RED << COLOR_BOLD
	          << "Could not find address for variable " << symbolName
	          << COLOR_NORM << COLOR_BOLD_OFF << std::endl;
	assert(false);
	return 0;
}

void ElfModuleLoader64::addSymbols() {
	SectionInfo symInfo =
	    this->elffile->findSectionByID(this->elffile->symindex);

	uint32_t symSize   = symInfo.size;
	Elf64_Sym *symBase = (Elf64_Sym *)symInfo.index;

	for (Elf64_Sym *sym = symBase;
	     sym < (Elf64_Sym *)(((char *)symBase) + symSize);
	     sym++) {
		if (sym->st_name == 0) {
			continue;
		}

		std::string symbolName = this->elffile->symbolName(sym->st_name);
		if (symbolName.compare("") == 0)
			continue;
		uint64_t symbolAddress = sym->st_value;

		if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL) {
			// Store local variables with uniq names
			symbolName.append("_").append(this->modName);
			std::string newSymName = symbolName;
			// int i = 2;
			// while (_funcTable.contains(newSymName)){
			//    newSymName = symbolName;
			//    newSymName.append("_").append(i);
			//}
			symbolName = newSymName;
		}

		if ((ELF64_ST_TYPE(sym->st_info) & (STT_OBJECT | STT_FUNC))) {
			if (ELF64_ST_BIND(sym->st_info) & STB_LOCAL) {
				symbolName.append("_");
				symbolName.append(this->getName());
			}
			this->kernel->addSymbolAddress(symbolName, symbolAddress);
		}

		// We also have to consider local functions
		// if((ELF64_ST_TYPE(sym->st_info) & STT_FUNC) &&
		// ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
		if ((ELF64_ST_TYPE(sym->st_info) == STT_FUNC)) {
			if (symbolAddress < (uint64_t) this->textSegment.memindex) {
				symbolAddress += (uint64_t) this->textSegment.memindex;
			}
			this->kernel->addFunctionAddress(symbolName, symbolAddress);
		}
	}
}
