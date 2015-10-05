#include "elfkernelloader.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfLoader* ElfKernelLoader::getModuleForCodeAddress(uint64_t address){
	
	//Does the address belong to the kernel?
	if (this->isCodeAddress(address)){
		return this;
	}

	for( auto& modulePair : moduleMap){
		ElfLoader* module = dynamic_cast<ElfLoader*>(modulePair.second);
		if (module->isCodeAddress(address)){
			return module;
		}
	}
	return 0;
}

ElfLoader* ElfKernelLoader::getModuleForAddress(uint64_t address){
	
	//Does the address belong to the kernel?
	if (this->isCodeAddress(address) || this->isDataAddress(address)){
		return this;
	}

	for( auto& modulePair : moduleMap){
		ElfLoader* module = dynamic_cast<ElfLoader*>(modulePair.second);
		if (module->isCodeAddress(address) || module->isDataAddress(address)){
			return module;
		}
	}
	return 0;
}

std::string ElfKernelLoader::getName(){
	return std::string("kernel");
}

ElfKernelLoader::ElfKernelLoader(ElfFile* elffile):
	ElfLoader(elffile, ParavirtState::getInstance()),
	KernelManager(),
	vvarSegment(),
	dataNosaveSegment(),
	fentryAddress(0),
	genericUnrolledAddress(0)
	{}

ElfKernelLoader::~ElfKernelLoader(){}

void ElfKernelLoader::initText(void) {

	ElfFile64* elffile = dynamic_cast<ElfFile64*>(this->elffile);

	this->textSegment = elffile->findSectionWithName(".text");
	this->updateSectionInfoMemAddress(this->textSegment);
	
	this->fentryAddress = this->elffile->findAddressOfVariable("__fentry__");
	this->genericUnrolledAddress = this->
			elffile->findAddressOfVariable("copy_user_generic_unrolled");

	applyAltinstr();
	applyParainstr();
	applySmpLocks();


	this->textSegmentContent.insert(this->textSegmentContent.end(),
			this->textSegment.index,
			this->textSegment.index + this->textSegment.size);


	SectionInfo info = elffile->findSectionWithName(".notes");
	uint64_t offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);

	info = elffile->findSectionWithName("__ex_table");
	offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
				offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);


	//Apply Ftrace changes
	info = elffile->findSectionWithName(".init.text");
	uint64_t initTextOffset = -(uint64_t) info.memindex + (uint64_t) info.index;

	info.index = (uint8_t *) elffile->findAddressOfVariable("__start_mcount_loc") + initTextOffset;
	info.size = (uint8_t *) elffile->findAddressOfVariable("__stop_mcount_loc") + initTextOffset - info.index;
	applyMcount(info);

	//TODO! also enable this some time later
	//Apply Tracepoint changes
	//    SectionInfo rodata = findElfSegmentWithName(fileContent, ".rodata");
	//    qint64 rodataOffset = - (quint64)rodata.address + (quint64)rodata.index;
	//    info.index = (char *)findElfAddressOfVariable(fileContent, context, "__start___tracepoints_ptrs") + rodataOffset;
	//    info.size = (char *)findElfAddressOfVariable(fileContent, context, "__stop___tracepoints_ptrs") + rodataOffset - info.index ;
	//    applyTracepoints(info, rodata, context, textSegmentContent);

	info = elffile->findSectionWithName(".data");
	int64_t dataOffset = -(uint64_t) info.memindex + (uint64_t) info.index;
	uint64_t jumpStart = elffile->findAddressOfVariable("__start___jump_table");
	uint64_t jumpStop = elffile->findAddressOfVariable("__stop___jump_table");

	info.index = (uint8_t *) jumpStart + dataOffset;
	info.size = (uint8_t *) jumpStop + dataOffset - info.index;

	//Save the jump_labels section for later reference.
	if (info.index != 0){
		this->jumpTable.insert(this->jumpTable.end(),
					info.index, info.index + info.size);
	}
    uint32_t numberOfEntries = (jumpStop - jumpStart) / sizeof(struct jump_entry);


	applyJumpEntries( jumpStart, numberOfEntries );

	this->textSegmentLength = this->textSegmentContent.size();
	uint32_t fill = 0x200000 - (this->textSegmentLength % 0x200000);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			fill, 0);

	this->addSymbols();
}

void ElfKernelLoader::initData(void){

	this->dataSection = elffile->findSectionWithName(".data");
	this->vvarSegment = elffile->findSectionWithName(".vvar");
	this->dataNosaveSegment = elffile->findSectionWithName(".data_nosave");
	this->bssSection = elffile->findSectionWithName(".bss");
	this->roDataSection = elffile->findSectionWithName(".rodata");

	this->idt_tableAddress = this->getSystemMapAddress("idt_table");
	this->nmi_idt_tableAddress = this->getSystemMapAddress("nmi_idt_table");
	this->sinittextAddress = this->getSystemMapAddress("_sinittext");
	this->irq_entries_startAddress = 
		this->getSystemMapAddress("irq_entries_start");


	// initialize roData Segment
	SectionInfo info = elffile->findSectionWithName("__modver");
	assert(info.index);
	this->roData.insert(this->roData.end(),
			roDataSection.index, info.index + info.size);
   
    this->roData.insert(this->roData.end(),
			0x200000 - (this->roData.size() % 0x200000), 0);
	
	this->roDataSection.size = this->roData.size();
}

void ElfKernelLoader::updateSectionInfoMemAddress(SectionInfo &info){
	UNUSED(info);
}

bool ElfKernelLoader::isDataAddress(uint64_t addr){
	return this->elffile->isDataAddress(addr | 0xffff000000000000);
}

