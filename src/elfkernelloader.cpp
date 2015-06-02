#include "elfkernelloader.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfLoader* ElfKernelLoader::getModuleForCodeAddress(uint64_t address){
	
	//Does the address belong to the kernel?
	if (this->isCodeAddress(address)){
		return this;
	}

	for( auto modulePair : moduleMap){
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

	for( auto modulePair : moduleMap){
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
	ElfLoader(elffile),
	KernelManager(),
	vvarSegment(),
	dataNosaveSegment(),
	rodataSegment(),
	fentryAddress(0),
	genericUnrolledAddress(0)
	{
	}

ElfKernelLoader::~ElfKernelLoader(){}

void ElfKernelLoader::initText(void) {

	ElfFile64* elffile = dynamic_cast<ElfFile64*>(this->elffile);

	this->textSegment = elffile->findSegmentWithName(".text");
	this->updateSegmentInfoMemAddress(this->textSegment);
	
	this->fentryAddress = this->elffile->findAddressOfVariable("__fentry__");
	this->genericUnrolledAddress = this->
			elffile->findAddressOfVariable("copy_user_generic_unrolled");

	applyAltinstr();
	applyParainstr();
	applySmpLocks();


	this->textSegmentContent.insert(this->textSegmentContent.end(),
			this->textSegment.index,
			this->textSegment.index + this->textSegment.size);


	SegmentInfo info = elffile->findSegmentWithName(".notes");
	uint64_t offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);

	info = elffile->findSegmentWithName("__ex_table");
	offset = (uint64_t) info.index - (uint64_t) this->textSegment.index;
	this->textSegmentContent.insert(this->textSegmentContent.end(),
				offset - this->textSegmentContent.size(), 0);
	this->textSegmentContent.insert(this->textSegmentContent.end(),
			info.index, info.index + info.size);


	//Apply Ftrace changes
	info = elffile->findSegmentWithName(".init.text");
	uint64_t initTextOffset = -(uint64_t) info.memindex + (uint64_t) info.index;

	info.index = (uint8_t *) elffile->findAddressOfVariable("__start_mcount_loc") + initTextOffset;
	info.size = (uint8_t *) elffile->findAddressOfVariable("__stop_mcount_loc") + initTextOffset - info.index;
	applyMcount(info);

	//TODO! also enable this some time later
	//Apply Tracepoint changes
	//    SegmentInfo rodata = findElfSegmentWithName(fileContent, ".rodata");
	//    qint64 rodataOffset = - (quint64)rodata.address + (quint64)rodata.index;
	//    info.index = (char *)findElfAddressOfVariable(fileContent, context, "__start___tracepoints_ptrs") + rodataOffset;
	//    info.size = (char *)findElfAddressOfVariable(fileContent, context, "__stop___tracepoints_ptrs") + rodataOffset - info.index ;
	//    applyTracepoints(info, rodata, context, textSegmentContent);

	info = elffile->findSegmentWithName(".data");
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

	this->dataSegment = elffile->findSegmentWithName(".data");
	this->vvarSegment = elffile->findSegmentWithName(".vvar");
	this->dataNosaveSegment = elffile->findSegmentWithName(".data_nosave");
	this->bssSegment = elffile->findSegmentWithName(".bss");
	this->roDataSegment = elffile->findSegmentWithName(".rodata");

	this->idt_tableAddress = this->getSystemMapAddress("idt_table");
	this->nmi_idt_tableAddress = this->getSystemMapAddress("nmi_idt_table");
	this->sinittextAddress = this->getSystemMapAddress("_sinittext");
	this->irq_entries_startAddress = 
		this->getSystemMapAddress("irq_entries_start");


	// initialize roData Segment
	SegmentInfo info = elffile->findSegmentWithName("__modver");
	assert(info.index);
	this->roData.insert(this->roData.end(),
			roDataSegment.index, info.index + info.size);
   
    this->roData.insert(this->roData.end(),
			0x200000 - (this->roData.size() % 0x200000), 0);
	
	this->roDataSegment.size = this->roData.size();

//	//TODO
//	//.data
//	//.vvar
//	QByteArray vvarSegmentContent = QByteArray();
//	vvarSegmentContent.append(context.vvarSegment.index,
//			context.vvarSegment.size);
//	for (int i = 0; i <= vvarSegmentContent.size() / 0x1000; i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = vvarSegmentContent.mid(i * 0x1000, 0x1000);
//		if (!segment.isEmpty()) {
//			segment = segment.leftJustified(0x1000, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.vvarSegmentData.append(page);
//		}
//	}
//	//.data_nosave
//	QByteArray dataNosaveSegmentContent = QByteArray();
//	dataNosaveSegmentContent.append(context.vvarSegment.index,
//			context.vvarSegment.size);
//	for (int i = 0; i <= dataNosaveSegmentContent.size() / 0x1000; i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = dataNosaveSegmentContent.mid(i * 0x1000, 0x1000);
//		if (!segment.isEmpty()) {
//			segment = segment.leftJustified(0x1000, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.dataNosaveSegmentData.append(page);
//		}
//	}
//	//.bss
//
}

void ElfKernelLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	UNUSED(info);
}

bool ElfKernelLoader::isDataAddress(uint64_t addr){
	return this->elffile->isDataAddress(addr | 0xffff000000000000);
	//addr = addr & 0xffffffffffff;
	//return (this->dataSegment.containsMemAddress(addr) ||
	//        this->vvarSegment.containsMemAddress(addr) || 
	//        this->dataNosaveSegment.containsMemAddress(addr) || 
	//        this->bssSegment.containsMemAddress(addr));
}
