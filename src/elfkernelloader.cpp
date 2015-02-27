#include "elfkernelloader.h"

#include "helpers.h"

#include "exceptions.h"
#include <cassert>

ElfLoader* ElfKernelLoader::getModuleForAddress(uint64_t address){
	
	//Does the address belong to the kernel?
	uint64_t text = ((uint64_t) this->textSegment.memindex & 0xffffffffffff);
	if (address >= text &&
	    address < text + this->textSegmentContent.size()){
		return this;
	}

	for( auto modulePair : moduleMap){
		ElfLoader* module = dynamic_cast<ElfLoader*>(modulePair.second);
		text = ((uint64_t) module->textSegment.memindex & 0xffffffffffff);
		if (address >= text && 
		    address < text + module->textSegmentContent.size()){
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
	bssSegment(),
	rodataSegment(),
	fentryAddress(0),
	genericUnrolledAddress(0)
	{}

ElfKernelLoader::~ElfKernelLoader(){}

void ElfKernelLoader::initText(void) {

	ElfFile64* elffile = dynamic_cast<ElfFile64*>(this->elffile);

	this->textSegment = elffile->findSegmentWithName(".text");
	this->updateSegmentInfoMemAddress(this->textSegment);
	
	this->dataSegment = elffile->findSegmentWithName(".data");
	this->vvarSegment = elffile->findSegmentWithName(".vvar");
	this->dataNosaveSegment = elffile->findSegmentWithName(".data_nosave");
	this->bssSegment = elffile->findSegmentWithName(".bss");


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
	uint64_t initTextOffset = -(uint64_t) info.address + (uint64_t) info.index;

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
	int64_t dataOffset = -(uint64_t) info.address + (uint64_t) info.index;
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
}

//TODO the following must also be put in its own function
//
//	// Hash
//	QCryptographicHash hash(QCryptographicHash::Sha1);
//
//	for (int i = 0;
//			i <= context.textSegmentContent.size() / KERNEL_CODEPAGE_SIZE;
//			i++) {
//		PageData page = PageData();
//		hash.reset();
//		// Caclulate hash of one segment at the ith the offset
//		QByteArray segment = context.textSegmentContent.mid(
//				i * KERNEL_CODEPAGE_SIZE, KERNEL_CODEPAGE_SIZE);
//		if (!segment.isEmpty()) {
//			//Remember how long the contents of the text segment are,
//			//this is to identify the uninitialized data
//			if (segment.size() != KERNEL_CODEPAGE_SIZE) {
//				if ((segment.size() + 1) % PAGE_SIZE != 0) {
//					quint32 size = segment.size();
//					size += PAGE_SIZE - (size % PAGE_SIZE);
//					context.textSegmentInitialized = i * KERNEL_CODEPAGE_SIZE
//							+ size;
//				}
//			}
//			segment = segment.leftJustified(KERNEL_CODEPAGE_SIZE, 0);
//			page.content = segment;
//			hash.addData(page.content);
//			page.hash = hash.result();
//			context.textSegmentData.append(page);
//		}
//		//Console::out() << "The " << i << "th segment got a hash of: " << segmentHashes.last().toHex() << " Sections." << endl;
//	}
//
void ElfKernelLoader::initData(void){

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
//
//	//Initialize the symTable in the context for later reference
//	if (fileContent[4] == ELFCLASS32) {
//		//TODO
//	} else if (fileContent[4] == ELFCLASS64) {
//		Elf64_Ehdr * elf64Ehdr = (Elf64_Ehdr *) fileContent;
//		Elf64_Shdr * elf64Shdr = (Elf64_Shdr *) (fileContent
//				+ elf64Ehdr->e_shoff);
//
//		quint32 symSize = elf64Shdr[context.symindex].sh_size;
//		Elf64_Sym *symBase = (Elf64_Sym *) (fileContent
//				+ elf64Shdr[context.symindex].sh_offset);
//
//		for (Elf64_Sym * sym = symBase;
//				sym < (Elf64_Sym *) (((char*) symBase) + symSize); sym++) {
//			//We also need to know about private functions for data verification, so also save them here.
//			//TODO fix scope
//			if (ELF64_ST_TYPE(sym->st_info) & (STT_FUNC)
//					|| (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE)))
//					//if(ELF64_ST_TYPE(sym->st_info) & (STT_FUNC) || (ELF64_ST_TYPE(sym->st_info) == (STT_NOTYPE) && ELF64_ST_BIND(sym->st_info) & STB_GLOBAL))
//					{
//				QString symbolName =
//						QString(
//								&((fileContent
//										+ elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//				quint64 symbolAddress = sym->st_value;
//				_funcTable.insert(symbolName, symbolAddress);
//			}
//			if (ELF64_ST_BIND(sym->st_info) & STB_GLOBAL) {
//				QString symbolName =
//						QString(
//								&((fileContent
//										+ elf64Shdr[context.strindex].sh_offset)[sym->st_name]));
//				quint64 symbolAddress = sym->st_value;
//				if (!_symTable.contains(symbolName)) {
//					_symTable.insert(symbolName, symbolAddress);
//				}
//			}
//		}
//	}
//
//	return context;
// end of parseElfFile()

void ElfKernelLoader::updateSegmentInfoMemAddress(SegmentInfo &info){
	info.memindex = (uint8_t *) info.address;
}
