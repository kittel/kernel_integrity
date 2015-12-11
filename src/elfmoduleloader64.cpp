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
