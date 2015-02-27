#include "elfmoduleloader64.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfModuleLoader64::ElfModuleLoader64(ElfFile64* elffile, 
		                             std::string name,
                                     KernelManager* parent):
	ElfModuleLoader(elffile, name, parent){
	this->parseElfFile();
}

ElfModuleLoader64::~ElfModuleLoader64(){}

void ElfModuleLoader64::applyRelocationsOnSection(uint32_t relSectionID){
	ElfFile64 *elf= dynamic_cast<ElfFile64 *>(this->elffile);
	assert(elf);

	SegmentInfo relSectionInfo = 
		        this->elffile->findSegmentByID(relSectionID);
	
    Elf32_Word sectionID = elf->elf64Shdr[relSectionID].sh_info;
	std::string sectionName = this->elffile->segmentName(sectionID);

	SegmentInfo sectionInfo = 
		        this->elffile->findSegmentByID(sectionID);
	this->updateSegmentInfoMemAddress(sectionInfo);
	Elf64_Rela *rel = (Elf64_Rela *) relSectionInfo.index;

    Elf64_Sym *symBase = (Elf64_Sym *) this->elffile->
	                     segmentAddress(this->elffile->symindex);

	SegmentInfo percpuDataSegment = 
	    this->elffile->findSegmentWithName(".data..percpu");
	Instance currentModule = this->parent->
	                               getKernelModuleInstance(this->modName);
	


#ifdef PRINTDEBUG
    bool doPrint = false;
    if(sectionName.compare("__kcrctab_gpl") == 0) doPrint = true;
    if(doPrint) Console::out() << "SectioN To Relocate: " << sectionName << dec << endl;
#endif
	
	SegmentInfo symRelSectionInfo;
	
    for (uint32_t i = 0; i < relSectionInfo.size / sizeof(*rel); i++) {
		void *locInElf = 0;
		void *locInMem = 0;
		void *locOfRelSectionInMem = 0;
		void *locOfRelSectionInElf = 0;

        /* This is where to make the change */
        locInElf = (void *) ((char*) sectionInfo.index    + rel[i].r_offset);
        locInMem = (void *) ((char*) sectionInfo.memindex + rel[i].r_offset);

		Elf64_Sym *sym = 0; 
        sym = symBase + ELF64_R_SYM(rel[i].r_info);

        switch(sym->st_shndx){
        case SHN_COMMON:

#ifdef PRINTDEBUG
            if(doPrint) Console::out() << "Symtype SHN_UNDEF" << endl;
            debugerr("This should not happen!");
#endif
			assert(false);
            continue; //TODO REMOVE
            break;
        case SHN_ABS:
#ifdef PRINTDEBUG
            if(doPrint) Console::out() << "Symtype SHN_ABS" << endl;
#endif
            break;
        case SHN_UNDEF:
#ifdef PRINTDEBUG
            if(doPrint) Console::out() << "Symtype SHN_UNDEF" << endl;
#endif
			sym->st_value = this->relocateShnUndef(
			                      this->elffile->symbolName(sym->st_name));
            break;
        default:
#ifdef PRINTDEBUG
            if(doPrint) Console::out() << "default: " << endl;
            //debugerr("Sym Type: default: " << sym->st_shndx);
#endif

            //TODO this is not right yet.
            /* Divert to percpu allocation if a percpu var. */
            if (sym->st_shndx == percpuDataSegment.segID){
                locOfRelSectionInMem = (void *) currentModule.
				                                    memberByName("percpu").
				                                    getValue<uint64_t>();
            }
            else
            {
				if (symRelSectionInfo.segID != sym->st_shndx){
					symRelSectionInfo = 
					    this->elffile->findSegmentByID(sym->st_shndx);
					this->updateSegmentInfoMemAddress(symRelSectionInfo);
				}
                locOfRelSectionInElf = (void *) symRelSectionInfo.index;
                locOfRelSectionInMem = (void *) symRelSectionInfo.memindex;
            }

            if(sym->st_value < (long unsigned int) locOfRelSectionInMem){
                sym->st_value += (long unsigned int) locOfRelSectionInMem;
            }
            break;
        }

        uint64_t val = sym->st_value + rel[i].r_addend;

#if PRINTDEBUG
		if(doPrint) Console::out() << "raddend: " << hex << rel[i].r_addend << dec << endl;
        if(doPrint) Console::out() << "sym->value: " << hex << sym->st_value << dec << endl;
        if(doPrint) Console::out() << "val: " << hex << val << dec << endl;
#endif

        switch (ELF64_R_TYPE(rel[i].r_info)) {
        case R_X86_64_NONE:
            break;
        case R_X86_64_64:
            *(uint64_t *)locInElf = val;
            break;
        case R_X86_64_32:
            *(uint64_t *)locInElf = val;
            if (val != *(uint64_t *)locInElf)
				assert(false);
			    return;
                //goto overflow;
            break;
        case R_X86_64_32S:
            *(uint32_t *)locInElf = val;
            if ((int64_t)val != *(int32_t *)locInElf)
				assert(false);
			    return;
                //goto overflow;
            break;
        case R_X86_64_PC32:

            // This line is from the original source the loc here is the
			//  location within the loaded module.

            //val -= (u64)loc;
            if(sectionName.compare(".altinstructions") == 0)
            {
                //This is later used to copy some memory
                val = val - (uint64_t)locOfRelSectionInMem + 
				            (uint64_t)locOfRelSectionInElf - 
				            (uint64_t)locInElf;
            }
            else
            {
                //This is used as relocation in memory
                val -= (uint64_t)locInMem;
            }
#ifdef PRINTDEBUG
            if(doPrint) Console::out() << "PC32 final value: " << hex << (quint32) val << dec << endl;
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
            debugerr("Unknown rela relocation: " << ELF64_R_TYPE(rel[i].r_info));
#endif
			assert(false);
		    return;
        }
#ifdef PRINTDEBUG
        doPrint = false;
#endif
    }
    return;

//#if 0
//overflow:
//    Console::err() << "overflow in relocation type " << (int)ELF64_R_TYPE(rel[i].r_info) << " val " << hex << val << endl;
//    Console::err() << "likely not compiled with -mcmodel=kernel" << endl;
//    return -ENOEXEC;
//#endif

}
uint64_t ElfModuleLoader64::relocateShnUndef(std::string symbolName){

	// First look into the system map.
	// As we depend on dwarf anyway we use that information to find
	// a variable.
	
	uint64_t address = this->parent->getSystemMapAddress(symbolName);
    if(address != 0){
        return address;
    }
	address = this->parent->getSymbolAddress(symbolName);
    if(address != 0){
        return address;
    }
	address = this->parent->getFunctionAddress(symbolName);
    if(address != 0){
        return address;
    }
#if 0
	// Assume we already have the correct object ...
	// Thus the following is not necessary
	// If it is, this section filteres weak objects
	
    else if (_sym.memSpecs().systemMap.count(symbolName) > 0)
    {
		//Try to find variable in system map
        //Console::out() << "Found Variable in system.map: " << symbolName) << endl;
        //sym->st_value = _sym.memSpecs().systemMap.value(symbolName).address;
        QList<SystemMapEntry> symbols = _sym.memSpecs().systemMap.values(symbolName);
        for (QList<SystemMapEntry>::iterator i = symbols.begin(); i != symbols.end(); ++i)
        {
            SystemMapEntry currentEntry = (*i);

            //ELF64_ST_BIND(sym->st_info) => 0: Local, 1: Global, 2: Weak
            //currentEntry.type => 'ascii' lowercase: local, uppercase: global
            if (ELF64_ST_BIND(sym->st_info) == 1 && currentEntry.type >= 0x41 && currentEntry.type <= 0x5a)
            {
                if(doPrint) Console::out() << "Symbol found in System Map: " << hex << currentEntry.address << " With type: Global" << dec << endl;
                sym->st_value = currentEntry.address;
            }
            else if (ELF64_ST_BIND(sym->st_info) == 0 && currentEntry.type >= 0x61 && currentEntry.type <= 0x7a)
            {
                if(doPrint) Console::out() << "Symbol found in System Map: " << hex << currentEntry.address << " With type: Local" << dec << endl;
                sym->st_value = currentEntry.address;
            }
        }
    }
#endif

	// Variable not found in system.map
    // Try to find the variable by name in insight.
    Function *func = Function::findFunctionByName(symbolName);
    if (func){
		return func->getAddress();
    }

	Variable *var = Variable::findVariableByName(symbolName);
    if (var){
		return var->getLocation();
	}
	assert(false);
	return 0;
}

void ElfModuleLoader64::addSymbols(){

    SegmentInfo symInfo = this->elffile->findSegmentByID(this->elffile->symindex);

    uint32_t symSize = symInfo.size;
    Elf64_Sym *symBase = (Elf64_Sym *) symInfo.index;

    for(Elf64_Sym * sym = symBase; 
	    sym < (Elf64_Sym *) (((char*) symBase) + symSize) ; 
	    sym++){

		if (sym->st_name == 0){
			continue;
		}
        
        std::string symbolName = this->elffile->symbolName(sym->st_name);

		if((ELF64_ST_TYPE(sym->st_info) & (STT_OBJECT | STT_FUNC)) && 
		    ELF64_ST_BIND(sym->st_info) & STB_GLOBAL )
        {
            uint64_t symbolAddress = sym->st_value;

            // TODO update symtable
			this->parent->addSymbolAddress(symbolName, symbolAddress);
        }

        //We also have to consider local functions
        //if((ELF64_ST_TYPE(sym->st_info) & STT_FUNC) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL)
        if((ELF64_ST_TYPE(sym->st_info) == STT_FUNC))
        {
            if(symbolName.compare("") == 0) continue;
            if (ELF64_ST_BIND(sym->st_info) == STB_LOCAL){
			    //Store local variables with uniq names
                symbolName.append("_").append(this->modName);
				std::string newSymName = symbolName;
                //int i = 2;
                //while (_funcTable.contains(newSymName)){
                //    newSymName = symbolName;
                //    newSymName.append("_").append(i);
                //}
                symbolName = newSymName;
            }
            uint64_t symbolAddress = sym->st_value;
            if(symbolAddress < (uint64_t) this->textSegment.memindex){
                symbolAddress += (uint64_t) this->textSegment.memindex;
            }
			this->parent->addFunctionAddress(symbolName, symbolAddress);
        }
    }

}