#include "elfmoduleloader.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfModuleLoader::ElfModuleLoader(ElfFile* elffile, 
	    std::string name,
		KernelManager* parent):
	ElfLoader(elffile),
	modName(name),
	parent(parent){
}

ElfModuleLoader::~ElfModuleLoader(){}

std::string ElfModuleLoader::getName(){
	return this->modName;
}

void ElfModuleLoader::loadDependencies(void) {
	SegmentInfo miS = elffile->findSegmentWithName(".modinfo");

	//parse .modinfo and load dependencies
	char *modinfo = (char*) miS.index;
	char *module = NULL;
	char *saveptr;
	if(!modinfo) return;

	while (modinfo < (char*) (miS.index) + miS.size)
	{
		//std::cout << "Searching for string" << std::endl;
		//check if the string starts with depends
		if(modinfo[0] == 0){
			modinfo++;
			continue;
		}else if(strncmp(modinfo, "depends", 7) != 0){
			modinfo += strlen(modinfo) + 1;
			continue;
		}else{
			//string.compare(0, 7, "depends")
			modinfo += 8;
			
			module = strtok_r(modinfo, ",", &saveptr);
			while(module != NULL){
				if(*module == 0) break;
				parent->loadModule(module);
				module = strtok_r(NULL, ",", &saveptr);
			}
			return;
		}
	}

}

void ElfModuleLoader::initText(void) {
	std::cout << COLOR_GREEN
	             "Loading dependencies for module " << this->modName;
	std::cout << COLOR_NORM << std::endl;

	this->loadDependencies();

	std::cout << COLOR_GREEN
	             "Loading module " << this->modName;
	std::cout << COLOR_NORM << std::endl;

	this->elffile->applyRelocations(this);
	
	this->textSegment = this->elffile->findSegmentWithName(".text");
	this->updateSegmentInfoMemAddress(this->textSegment);

    //applyJumpEntries();

	applyAltinstr();
	applyParainstr();
	applySmpLocks();
	
    //Content of text section in memory:
    //same as the sections in the elf binary

    this->textSegmentContent.clear();
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			this->textSegment.index,
			this->textSegment.index + this->textSegment.size);

	uint8_t *fileContent = this->elffile->getFileContent();
    Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
    Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);
    for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
    {
		std::string sectionName = this->elffile->segmentName(i);
        if (sectionName.compare(".text") == 0 ||
            sectionName.compare(".init.text") == 0){
			continue;
		}

        if(elf64Shdr[i].sh_flags == (SHF_ALLOC | SHF_EXECINSTR)){
			this->textSegmentContent.insert(this->textSegmentContent.end(),
			      fileContent + elf64Shdr[i].sh_offset, 
			      fileContent + elf64Shdr[i].sh_offset + elf64Shdr[i].sh_size);
        }
    }

	// Fill up the last page
	this->textSegmentLength = this->textSegmentContent.size();
	uint32_t fill = 0x1000 - (this->textSegmentLength % 0x1000);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			fill, 0);

	SegmentInfo info = this->elffile->findSegmentWithName("__mcount_loc");
	this->updateSegmentInfoMemAddress(info);
    applyMcount(info);

	//TODO resume here

//    //Save the jump_labels section for later reference.
//
//    info = findElfSegmentWithName(fileContent, "__jump_table");
//    if(info.index != 0) context.jumpTable.append(info.index, info.size);
//
//    updateKernelModule(context);

    //Initialize the symTable in the context for later reference
	this->addSymbols();

//    context.rodataSegment = this->findElfSegmentWithName(context.fileContent, QString(".note.gnu.build-id"));
//    context.rodataSegment.address = (this->findMemAddressOfSegment(context, QString(".note.gnu.build-id")));
//
//    context.rodataContent.clear();
//    
//    // Populate rodata
//    Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//    Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent + elf64Ehdr->e_shoff);
//    for(unsigned int i = 0; i < elf64Ehdr->e_shnum; i++)
//    {
//        if(((elf64Shdr[i].sh_flags == SHF_ALLOC  || elf64Shdr[i].sh_flags == (uint64_t) 0x32) &&
//                ( elf64Shdr[i].sh_type == SHT_PROGBITS )) ||
//             (elf64Shdr[i].sh_flags == SHF_ALLOC && elf64Shdr[i].sh_type == SHT_NOTE))
//        {
//            QString sectionName = QString(fileContent + elf64Shdr[elf64Ehdr->e_shstrndx].sh_offset + elf64Shdr[i].sh_name);
//            if(sectionName.compare(QString(".modinfo")) == 0 ||
//                   sectionName.compare(QString("__versions")) == 0 ||
//                   sectionName.startsWith(".init") ) continue;
//            uint64_t align = (elf64Shdr[i].sh_addralign ?: 1) - 1;
//            uint64_t alignmentSize = (context.rodataContent.size() + align) & ~align;
//            context.rodataContent = context.rodataContent.leftJustified(alignmentSize, 0);
//            context.rodataContent.append(fileContent + elf64Shdr[i].sh_offset, elf64Shdr[i].sh_size);
//
////            std::cout << hex << "Adding Section "
////                           << context.currentModule.member("name").toString() << " / " << sectionName
////                           << " Align: " << alignmentSize << " Size: " << elf64Shdr[i].sh_size
////                           << dec << std::endl;
//        }
//    }
//
//    //writeModuleToFile(fileName, currentModule, fileContent );
//    return context;

}

void ElfModuleLoader::initData(void) {
	this->dataSegment = this->elffile->findSegmentWithName(".data");
	this->updateSegmentInfoMemAddress(this->dataSegment);
	this->bssSegment = elffile->findSegmentWithName(".bss");
	this->updateSegmentInfoMemAddress(this->bssSegment);
	this->roDataSegment = elffile->findSegmentWithName(".note.gnu.build-id");
	this->updateSegmentInfoMemAddress(this->roDataSegment);

	// initialize roData Segment
	ElfFile64* elf64 = dynamic_cast<ElfFile64*>(this->elffile);
    Elf64_Shdr * elf64Shdr = elf64->elf64Shdr;
    for(unsigned int i = 0; i < elf64->elf64Ehdr->e_shnum; i++)
    {
        if(((elf64Shdr[i].sh_flags == SHF_ALLOC  || 
			 elf64Shdr[i].sh_flags == SHF_STRINGS) &&
             elf64Shdr[i].sh_type == SHT_PROGBITS ) ||
             (elf64Shdr[i].sh_flags == SHF_ALLOC && 
			  elf64Shdr[i].sh_type == SHT_NOTE))
        {
			std::string sectionName = this->elffile->segmentName(i);
            if(sectionName.compare(".modinfo") == 0 ||
                   sectionName.compare("__versions") == 0 ||
                   sectionName.substr(0,5).compare(".init") == 0 ) continue;
            uint64_t align = (elf64Shdr[i].sh_addralign ?: 1) - 1;
            uint64_t alignmentSize = (this->roData.size() + align) & ~align;
			this->roData.insert(this->roData.end(),
				alignmentSize - this->roData.size(), 0);
			this->roData.insert(this->roData.end(),
				this->elffile->getFileContent() + elf64Shdr[i].sh_offset,
				this->elffile->getFileContent() + 
						elf64Shdr[i].sh_offset + elf64Shdr[i].sh_size);
        }
    }
	this->roDataSegment.size = this->roData.size();
}

uint8_t *ElfModuleLoader::findMemAddressOfSegment(SegmentInfo &info){

	std::string segName = info.segName;
	Instance module;
	Instance currentModule = this->parent->
	                               getKernelModuleInstance(this->modName);
	
	//If the searching for the .bss section
    //This section is right after the modules struct
	if(segName.compare(".bss") == 0){
		uint64_t align = this->elffile->segmentAlign(info.segID);
	
		uint64_t offset = currentModule.size() % align;
		(offset == 0)
		   	? offset = currentModule.size()
			: offset = currentModule.size() + align - offset;

        return (uint8_t *) currentModule.getAddress() + offset;
	}
	
	if(segName.compare("__ksymtab_gpl") == 0){
        return (uint8_t *) currentModule.memberByName("gpl_syms").
		                                 getRawValue<uint64_t>();
	}
	
	//Find the address of the current section in the memory image
    //Get Number of sections in kernel image
    Instance attrs = currentModule.memberByName("sect_attrs", true);
    uint32_t attr_cnt = attrs.memberByName("nsections").getValue<uint64_t>();

    //Now compare all section names until we find the correct section.
    for (uint j = 0; j < attr_cnt; ++j) {
        Instance attr = attrs.memberByName("attrs").arrayElem(j);
		std::string sectionName = attr.memberByName("name", true).
		                               getValue<std::string>();
		if(sectionName.compare(segName) == 0){
            return (uint8_t *) attr.memberByName("address").getValue<uint64_t>();
        }
    }
    return 0;
}

/* Update the target virtual address of the segment */
void ElfModuleLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	info.memindex = this->findMemAddressOfSegment(info);
}

bool ElfModuleLoader::isDataAddress(uint64_t addr){
	addr = addr | 0xffff000000000000;
	return (this->dataSegment.containsMemAddress(addr) ||
	        this->bssSegment.containsMemAddress(addr));
}
