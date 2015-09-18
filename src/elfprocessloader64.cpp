#include "elfprocessloader64.h"

#define PAGESIZE 0x1000

ElfProcessLoader64::ElfProcessLoader64(ElfFile64 *file, 
		KernelManager *parent,
		std::string name)
									   : ElfProcessLoader(file, parent, name),
										 bindLazy(true) {
	this->execName = name;
#ifdef DEBUG
	std::cout << "ElfProcessLoader64 initialized!" << std::endl;
#endif
}

ElfProcessLoader64::~ElfProcessLoader64(){}

/* Beginning body of the loader */

/* Get the vmem address of the first memory segment */
uint64_t ElfProcessLoader64::getTextStart(){
	return (uint64_t) this->textSegment.memindex;
}

uint64_t ElfProcessLoader64::getDataStart(){
	return (uint64_t) this->dataSection.memindex;
}

/* Get the size of the dataSection */
uint32_t ElfProcessLoader64::getDataSize(){
	return this->dataSection.size;
}
/* Get the size of the textSegment */
uint32_t ElfProcessLoader64::getTextSize(){
	return this->textSegment.size;
}

std::vector<RelSym*> ElfProcessLoader64::getProvidedSyms(){
	return this->providedSyms;
}

/* Supply heap information to the Loader */
void ElfProcessLoader64::setHeapSegment(SectionInfo* heap){
	this->heapSection = *heap;
}


/*
 * For relocatable objects: Update the memindex value [defining where this .so
 * is located in the calling process' address space].
 */
void ElfProcessLoader64::updateMemIndex(uint64_t addr, uint8_t segNr){

	std::string section;
	SectionInfo *seg;
	switch(segNr){ // extendable with Macros in util.h

		case SEG_NR_DATA:
				seg = &this->dataSection;
				section = "data";
				break;
		case SEG_NR_TEXT:
		default:
				seg = &this->textSegment;
				section = "text";
				break;
	}

	if(!this->elffile->isExecutable()){
#ifdef DEBUG
		std::cout << "debug: Library " << getNameFromPath(this->execName)
		<< " is updating ["
		<< section << "] memindex (" << std::hex
		<< (void*) seg->memindex << ") to " << (void*) addr << std::endl;
#endif
		seg->memindex = (uint8_t*) addr;
	}
}

/* Check if the given virtual address is located in the textSegment */
bool ElfProcessLoader64::isCodeAddress(uint64_t addr){

	// get offset to last page border
	uint64_t endAddr = ((uint64_t)this->textSegment.memindex)
						+ (this->textSegmentInfo.offset & 0xfff)
						+ this->textSegmentInfo.memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if(addr >= ((uint64_t)this->textSegment.memindex)
		&& addr < (endAddr + offset)){ 
		return true;
	}
	else return false;
}


/* Check if the given virtual address is located in the dataSection */
bool ElfProcessLoader64::isDataAddress(uint64_t addr){

	// get offset to last page border
	uint64_t endAddr = ((uint64_t)this->dataSection.memindex)
						+(this->dataSegmentInfo.offset & 0xfff)
						+ this->dataSegmentInfo.memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if(addr >= ((uint64_t)this->dataSection.memindex)
		&& addr < (endAddr + offset)){ 
		return true;
	}
	else return false;
}

/* Check if the given fileOffset (in bytes) lays in the textSegment */
bool ElfProcessLoader64::isTextOffset(uint64_t off){
	uint64_t pagedDataOff = (this->dataSegmentInfo.offset
								- (this->dataSegmentInfo.offset & 0xfff));
	if(off >= this->textSegmentInfo.offset && off < pagedDataOff) return true;
	else return false;
}

/* Check if the given fileOffset (in bytes) lays in the dataSection */
bool ElfProcessLoader64::isDataOffset(uint64_t off){
	uint64_t pagedDataOff = (this->dataSegmentInfo.offset
								- (this->dataSegmentInfo.offset & 0xfff));
	if(off >= pagedDataOff) return true;
	else return false;
}


uint64_t ElfProcessLoader64::getDataOff(){
	return this->dataSegmentInfo.offset;
}

uint64_t ElfProcessLoader64::getTextOff(){
	return this->textSegmentInfo.offset;
}

/* Append the stated memory segment to the given image */
uint32_t ElfProcessLoader64::appendSegToImage(SectionInfo *segment,
                                              std::vector<uint8_t> *target,
                                              uint32_t offset){

	uint8_t *startit = segment->index; // iterator to section content
	uint8_t *endit	 = segment->index + segment->size;
	if(offset != 0){
		std::vector<uint8_t> off;
		off.assign(offset, 0x0);
		target->insert(target->end(), off.begin(), off.end());
	}

	target->insert(target->end(), startit, endit);
	return segment->size + offset;
}

/* Append the stated vector to the given image */
uint32_t ElfProcessLoader64::appendVecToImage(std::vector<uint8_t> *src,
                                              std::vector<uint8_t> *target){
	auto startit = std::begin(*target);
	auto endit = std::end(*target);
	target->insert(target->end(), startit, endit);
	return src->size();
}


/* Print the currently assembled ProcessImage */
void ElfProcessLoader64::printImage(){
	std::cout << "Content of the current textSegment (" << this->execName
	<< "):" << std::endl;
	printHexDump(&(this->textSegmentContent));
	std::cout << "Content of the current dataSection (" << this->execName
	<< "):" << std::endl;
	printHexDump(&(this->dataSectionContent));	

/*
	for(auto it = std::begin(textSegmentContent); it != std::end(textSegmentContent); it++){
		printf("%c", *it);
	}
*/
}

/* Add the specified sections to the given memory Segment
 *
 * If invoking, set prevMemAddr = $(Start address of memory segment)
 *                  prevSecSize = 0
 *
 * for working offset initalization
 */
//void ElfProcessLoader64::addSectionsToSeg(int nrSecHeaders,
//                                          int prevMemAddr, int prevSecSize,
//                                          uint64_t startAddr, uint64_t endAddr,
//                                          SectionInfo *handler,
//                                          std::vector<uint8_t> *target,
//                                          uint32_t *targetLength){
//    int id = 0;
//    uint32_t offset = 0;
//	std::string strtarget;
//
//	if(target == &this->textSegmentContent) strtarget = "Text";
//	if(target == &this->dataSectionContent) strtarget = "Data";
//
//	// add all sections below endAddr to the target Segment
//	for(id = 0; id < nrSecHeaders; id++){
//
//        uint32_t flags = elf->elf64Shdr[id].sh_flags;
//		if(((flags & SHF_ALLOC) == SHF_ALLOC)){ 
//
//			*handler = elf->findSectionByID(id);
//
//
//
//			// if the current processed segment is .bss, and were processing the 
//			// dataSection, fill with 0x0 until page border
//			if(handler->segName.compare(".bss") == 0 && target == &this->dataSectionContent){
//#ifdef VERBOSE
//				std::cout << "Found .bss section. Filling with 0x0 until next page border..."
//				<< std::endl;
//#endif
//				uint64_t bssStart = (uint64_t) elf->elf64Shdr[id].sh_offset;
//				uint64_t offsetToBorder = PAGESIZE - (bssStart & 0xfff);
//				std::vector<uint8_t> zeroes;
//				zeroes.assign(offsetToBorder, 0x0);
//				this->dataSectionLength += appendDataToVector(zeroes.data(),
//															 offsetToBorder,
//															 &this->dataSectionContent);
//				prevMemAddr = elf->elf64Shdr[id].sh_addr;
//				prevSecSize = elf->elf64Shdr[id].sh_size;
//				return;
//			}
//
//			// if the current segment is _not_ .bss but has type NOBITS (e.g. .tbss)
//			// simply ignore it and don't add any bytes to the image
//			if(elf->elf64Shdr[id].sh_type == SHT_NOBITS){
//				continue;
//			}
//
//
//            if((elf->elf64Shdr[id].sh_addr < endAddr && elf->elf64Shdr[id].sh_addr >= startAddr)){
//
//    			offset = elf->elf64Shdr[id].sh_addr - (prevMemAddr + prevSecSize);
//#ifdef DEBUG
//    			std::cout << "debug: offset = 0x" << std::hex << offset << std::endl;
//    			if(offset != 0){
//    				std::cout << "Offset of 0x" << std::hex << offset << " bytes "
//                              << "found before " << handler->segName
//                              << std::endl;
//			    }
//#endif
//#ifdef VERBOSE
//		    	std::cout << "Adding section [" << std::dec << id << "] " << handler->segName
//                << " to " << strtarget <<"-Segment at 0x" << std::hex << (*targetLength)
//                << " + 0x" << (int)offset << std::endl;
//#endif
//				(*targetLength) += this->appendSegToImage(handler,
//                                                              target,
//                                                              offset);
//#ifdef DEBUG
//				std::cout << "debug: targetLength=" << std::hex << (*targetLength)
//						  << std::endl;
//#endif
//				prevMemAddr = elf->elf64Shdr[id].sh_addr;
//				prevSecSize = elf->elf64Shdr[id].sh_size;
//			}
//		}
//	}
//}

void ElfProcessLoader64::appendEhdr(){
	ElfFile64* elf = dynamic_cast<ElfFile64*>(this->elffile);
	this->textSegmentLength += appendDataToVector(elf->elf64Ehdr,
                                                  elf->elf64Ehdr->e_ehsize,
                                                  &(this->textSegmentContent));
}
void ElfProcessLoader64::appendPhdr(){
	ElfFile64* elf = dynamic_cast<ElfFile64*>(this->elffile);
	this->textSegmentLength += appendDataToVector(elf->elf64Phdr,
                                                  (elf->elf64Ehdr->e_phentsize*
                                                  elf->elf64Ehdr->e_phnum),
                                                  &(this->textSegmentContent));
}

/*
 * This method initializes the first big memory segment, which is loaded into
 * the process image. This segment is executable and often referred to as the
 * '.text' segment. Starting with the characteristic ELF-Header and PHT,
 * it usually contains the following sections in this or a similar order:
 *
 *	- .interp				name of the used dynamic loader/linker [~ld-linux]
 *	- .note.ABI-tag			supplementary information for other programs
 *	- .note.gnu.build-id	[dito]
 *	- .gnu.hash				hash table to support symbol table access
 *	- .dynsym				symbol table containing only syms relevant for rels
 *	- .dynstr				string table containing only names relevant for rels
 *	- .gnu.version			library compatibility informations
 *	- .gnu.version_r		[dito]
 *	- .rela.dyn				relocation entries for symbols
 *	- .rela.plt				relocation entries for function calls [see lazybind]
 *	- .init					program initialization code
 *	- .plt					procedure linkage table
 *	- .text					actual program instructions
 *	- .fini					program termination code
 *	- .rodata				read-only data, e.g. constants/output strings
 *	- .eh_frame_hdr			excpetion handling information
 *	- .eh_frame				[dito]
 *
 *	These section should lay simply concatenated in memory, as stated by the
 *	section header and program header table.
 *
 *	At the bottom of the textSegment resides a padding until the next page
 *	boundary, containing information from the dataSection.
 *
 *	The actual data of the process image is stored in 'textSegmentContents'
 *	which is a std::vector<uint8_t>, basically a dynamic byte array.
 *
 *	The actual order of the different sections may vary from file to file.
 *	However, it is given by the section ID.
 *
 *	We then subsequently append the needed sections to the process image.
 *	The resulting ProcessImage is not yet subject to relocations of any kind!
 *
 */

void ElfProcessLoader64::initText(){ // TODO currently only works for PDC

//	uint64_t prevMemAddr = 0; // for inter-section offset calculation
//	int prevSecSize = 0; // memsize of previous section

	this->textSegmentInfo = this->elffile->findCodeSegment();
	this->dataSegmentInfo = this->elffile->findDataSegment();

	this->appendEhdr();
	this->appendPhdr();

	return;

//	prevSecSize = 0; //dirty init for working inter-section offsets
//	prevMemAddr = elf->elf64Shdr[1].sh_addr;

    // add all sections in the text segment of the ELF-File to textSegmentContent
	// TODO XXX
    //this->addSectionsToSeg(nrSecHeaders, prevMemAddr, prevSecSize,
    //                       this->textSegmentInfo.vaddr, this->dataSegmentInfo.vaddr,
    //                       &(this->textSegment), &(this->textSegmentContent),
    //                       &(this->textSegmentLength));

	/*
	 * If this is a dynamic linked binary, clear the space after the last added
	 * section (set to 0x0) until the page boundary (0x1000) and (depending)
	 * add first bytes from dataSection at corresponding address
	 */
/*
	if(this->elffile->isDynamic()){
#ifdef DEBUG
		std::cout << "Found dynamic exec, clearing ending of textSegment and "
		<< "merging with dataSection border..." << std::endl;
#endif

	//stupidly write bytes from dataSection until page border is reached.
		uint64_t startWrite = elf->elf64Shdr[this->dataSegSHTid-1].sh_offset + 
				elf->elf64Shdr[this->dataSegSHTid-1].sh_size;
		uint64_t zeroLine = elf->elf64Shdr[this->dataSegSHTid].sh_offset;
		uint64_t endWrite = PAGESIZE;
		uint32_t len = endWrite - (zeroLine & 0xfff);
		uint8_t *fileContent = this->elffile->getFileContent();
		this->textSegmentContent.insert(std::end(this->textSegmentContent),
		                                zeroLine-startWrite, 0x0);
		this->textSegmentLength += (zeroLine-startWrite);
		this->textSegmentLength +=
		   appendDataToVector(fileContent + zeroLine,
		                      len, &this->textSegmentContent);
	}
*/

	/* 
	 * Update this->textSegment to match an actual memory segment from PHT
	 * rather than a section. After this, this->textSegment can be used for
	 * handling the memory segment (e.g. by the ProcessValidator).
	 */
//	this->textSegment.segName = (elf->getFilename()).append(".textSegment");
//	this->textSegment.segID = this->textSegPHTid;
//	this->textSegment.index = this->textSegmentContent.data();
//	this->textSegment.memindex = (uint8_t*) this->textSegmentInfo.vaddr;
//	this->textSegment.size = this->textSegmentLength;

	// check alignment (p_vaddr - p_offset % p_align == 0)
	auto entryPoint =  (uint64_t) this->textSegmentInfo.vaddr - this->textSegmentInfo.offset;
	if( entryPoint % this->textSegmentInfo.align != 0){
		std::cout << "error: alignment of PHDR broken!" << std::endl
		<< "p_vaddr: " << (this->textSegmentInfo.vaddr)
		<< " || offset: " << this->textSegmentInfo.offset
		<< " || p_align: " << this->textSegmentInfo.align << std::endl;

		}
	else{ // if the alignment values are correct
		//determine the correct page-aligned memindex (p_vaddr - p_offset).
		//TODO until now, not needed in the textSegment
#ifdef DEBUG
		std::cout << "debug: alignment values correct. new memindex would be: " << entryPoint << std::endl;
#endif
	}

/* Clean up */
}

/*
 * This Method initializes the second big memory segment of the processImage.
 * 
 * At the top resides a padding containing the last bytes of the textSegment.
 *
 * It is followed by the concatenated rw-sections.
 *
 */
void ElfProcessLoader64::initData(){
/*
#ifdef DEBUG
	std::cout << "debug: initializing dataSection of " << this->execName << std::endl;
#endif

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int nrSecHeaders = elf->getNrOfSections();
	this->dataSectionLength = 0;
    uint64_t prevMemAddr = 0; // for inter-section offset calculation
	int prevSecSize = 0; // memsize of previous section
	uint64_t endAddr = 0;


	// calculate endAddr of dataSection. PHTids should be set by now [initText].
	endAddr = this->dataSegmentInfo.vaddr + (uint64_t) this->dataSegmentInfo.memsz;


	// insert page padding from text segment

	uint8_t *fileContent = this->elffile->getFileContent();
	// get actual starting point of data
	uint64_t dataLine = elf->elf64Shdr[dataSegSHTid].sh_offset;
	// get the starting point of the information to include from text
	uint64_t pageStart = dataLine - (dataLine & (0xfff));
	// insert everything between
	this->dataSectionLength += appendDataToVector(fileContent + pageStart,
	                                              (dataLine - pageStart),
	                                              &this->dataSectionContent);

#ifdef DEBUG
	std::cout << "debug: (initData) init endAddr=" << std::hex <<  (void*)endAddr << std::endl;
#endif


	// add regular sections contained in the dataSection
	prevMemAddr = elf->elf64Shdr[dataSegSHTid].sh_addr;
	//this->addSectionsToSeg(nrSecHeaders, prevMemAddr, prevSecSize,
    //                       this->dataSegmentInfo.vaddr, endAddr,
    //                       &(this->dataSection), &(this->dataSectionContent),
    //                       &(this->dataSectionLength));


    // Update this->dataSection to match an actual memory segment.
//    this->dataSection.segName = (elf->getFilename()).append(".dataSection");
//	this->dataSection.segID = this->dataSegPHTid;
//	this->dataSection.index = this->dataSectionContent.data();
//// next value is obsolete if page alignment is taken into account
////	this->dataSection.memindex = (uint8_t*) this->dataSegmentInfo.vaddr;
//	this->dataSection.size = this->dataSectionLength; // TODO is this already page-aligned?
	
	// page alignment and sanity check
	uint64_t align =  this->dataSegmentInfo.vaddr - this->dataSegmentInfo.offset;
	if( align % this->dataSegmentInfo.align != 0){
			std::cout << "error: alignment of PHDR broken!" << std::endl
			<< "p_vaddr: " << (this->dataSegmentInfo.vaddr)
			<< " || offset: " << this->dataSegmentInfo.offset
			<< " || p_align: " << this->dataSegmentInfo.align << std::endl;
		}
	else{ // if the alignment values are correct
		//determine the correct page-aligned memindex (p_vaddr - (p_offset & 0xfff)).
			uint64_t entryPoint = (this->dataSegmentInfo.vaddr -
			                       (this->dataSegmentInfo.offset & 0xfff));
#ifdef DEBUG
			std::cout << "debug: new page aligned memindex for dataSection would be: "
			<< std::hex << (void*) entryPoint << std::endl;
#endif
			this->dataSection.memindex = (uint8_t*) entryPoint;
		}

	// Clean Up
*/

}



/* Return the ASLR offsets for the current process address space */
uint64_t ElfProcessLoader64::getOffASLR(uint8_t type){

	// TODO: find out how to gather the respective ASLR Offset

	switch(type){
		case ASLR_BRK:
		case ASLR_STACK:
		case ASLR_VDSO:
        default:            break;
	}
    return 0x0;
}


/* Initialize our providedSyms to prepare for relocation */
void ElfProcessLoader64::initProvidedSymbols(){

	// if this is a static exec we don't provide anything
	if(!this->elffile->isDynamic()) return;

	std::cout << "Initializing provided symbols of " << getNameFromPath(this->execName)
	<< " ..." << std::endl;

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	SectionInfo dynamic = elf->findSectionWithName(".dynamic");
	// use symtab instead of dynsym?
	SectionInfo symtab = elf->findSectionWithName(".dynsym"); 
	SectionInfo strtab = elf->findSectionWithName(".dynstr");

	Elf64_Dyn *dynsec = (Elf64_Dyn*) dynamic.index;
	Elf64_Sym *normsymtab = (Elf64_Sym*) symtab.index;

	char *normstrtab = (char*) strtab.index;
	uint16_t symSize = 0; // size of a .dynsym entry
	uint32_t normentries = 0; // amount of entries in .symtab	

	for(int i = 0; dynsec[i].d_tag != DT_NULL; i++){
		if(dynsec[i].d_tag == DT_SYMENT){
			symSize = dynsec[i].d_un.d_val;
			break;
		}
	}

	if(symSize == 0){
		std::cout << "error:(initProvidedSymbols) Couldn't determine symbol"
		<< " table entry size. Aborting." << std::endl;
		return;
	}

	normentries = symtab.size / symSize;
	std::string input;
	uint64_t targetAddr; // this is final memory address after loading 

	// initialize own symbols
	for(unsigned int i = 0; i < normentries; i++){
		// if symbol is GLOBAL and _not_ UNDEFINED save it for announcement
		if(ELF64_ST_BIND(normsymtab[i].st_info) == STB_GLOBAL
			&& normsymtab[i].st_shndx != SHN_UNDEF
			&& normsymtab[i].st_shndx != SHN_ABS
			&& normsymtab[i].st_shndx != SHN_COMMON){
			input.append(&normstrtab[normsymtab[i].st_name]);

			targetAddr = this->getVAForAddr(normsymtab[i].st_value,
											normsymtab[i].st_shndx);

			RelSym *sym = new RelSym(input,
									targetAddr,
									normsymtab[i].st_info,
									normsymtab[i].st_shndx,
									this);

			this->providedSyms.push_back(sym);

#ifdef DEBUG
			std::cout << "debug:(InitProvidedSymbols) Provided Symbol[GLOBAL]: "
			<< input
			<< ". Index: " << i << std::endl;
#endif
			input.clear();
		}
		if(ELF64_ST_BIND(normsymtab[i].st_info) == STB_WEAK
			&& normsymtab[i].st_shndx != SHN_UNDEF
			&& normsymtab[i].st_shndx != SHN_ABS
			&& normsymtab[i].st_shndx != SHN_COMMON){

			input.append(&normstrtab[normsymtab[i].st_name]);

			targetAddr = this->getVAForAddr(normsymtab[i].st_value,
											normsymtab[i].st_shndx);

			RelSym *sym = new RelSym(input,
									targetAddr,
									normsymtab[i].st_info,
									normsymtab[i].st_shndx,
									this);

			this->providedSyms.push_back(sym);

#ifdef DEBUG
			std::cout << "debug:(InitProvidedSymbols) Provided Symbol[WEAK]: "
			<< input
			<< ". Index: " << i << std::endl;
#endif
			input.clear();
		}
	}
}

/* Return the final memory address in the procImg for the given addr
 *
 *  - get the offset from file start for the address
 *  - translate the offset in an offset into text/dataSection
 *  - return text/dataSection->memindex + segOffset
 *
 * */
uint64_t ElfProcessLoader64::getVAForAddr(uint64_t addr, uint32_t shtID){

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	uint64_t off = elf->elf64Shdr[shtID].sh_offset; // offset to cont. section
	// offset to symbol address from section start
	uint64_t symOff = addr - elf->elf64Shdr[shtID].sh_addr;
	uint64_t va = 0;

	if(this->isTextOffset(off)){
		va = (((uint64_t)this->textSegment.memindex) + off + symOff);
	}
	else if(this->isDataOffset(off)){
		va = (((uint64_t)this->dataSection.memindex)
				+ (off - this->dataSegmentInfo.offset) // offset into dataSection
				+ symOff);                     // offset to target symbol
	}
	else{
		std::cout << "error:(getVAForAddr) Couldn't find VA for addr "
		<< (void*) addr << ", offset "
		<< (void*)off << " in SHT [" << std::dec << shtID << "]. "
		<< "Returning dataSection..." << std::endl;
		return (uint64_t)this->dataSection.memindex;
	}

	return va;
}


/* Try to process relocation for the given (final) virtual addr.
 *
 * This function only gets called on demand and returns an error value
 * if this loader is not employing LazyBinding or the addr doesn't correspond
 * to an unresolved .got.plt entry
 *
 * - sanity checks
 * - determine corresponding segment
 * - determine offset into segment from given vaddr
 * - Sweep through all instantiated rel/rela entries
 * - if (offset corresponds to entry)
 *     - if (entry is JUMP_SLOT
 *         - relocate
 *         - return 0
 * - return 1
 */
int ElfProcessLoader64::evalLazy(uint64_t addr,
								std::unordered_map<std::string, RelSym*> *map){

	std::string debug;

	// if the entry should've already been processed
	if(this->bindLazy == false) return 1;

	uint64_t off = 0; // offset of symbol into corresponding segment (independent)
	uint64_t relOff = 0; // r_offset which should correspond to the right rel/a entry
                         // FILE REPRESENTATION!
	uint64_t dataVecBaseAddr; // starting address (FILE REPRESENTATION) of data
                              // vector content (including padding)

	if(this->isCodeAddress(addr)){
		off = addr - ((uint64_t)this->textSegment.memindex);
		debug = "code";
	}
	else if(this->isDataAddress(addr)){
		off = addr - ((uint64_t)this->dataSection.memindex);
		debug = "data";
	}
	else{
		std::cout << "error:(evalLazy@" << getNameFromPath(this->execName)
		<< ") Given addr " << (void*)addr << " is not contained in any segment!"
		<< std::endl
		<< "off: " << (void*)off << ", relOff: " << (void*)relOff << std::endl;
		return 1;
	}
	// recognize textSeg padding from last page border
	dataVecBaseAddr = (uint64_t) this->dataSegmentInfo.vaddr -
	                             ((uint64_t) this->dataSegmentInfo.vaddr & 0xfff);
	relOff = off + dataVecBaseAddr;
#ifdef DEBUG
	std::cout << "debug:(evalLazy) addr = " << (void*)addr << ", offset into "
	<< debug << " segment " << (void*)off << std::endl;
#endif
	// find corresponding rel/rela entry
	for(auto it = this->rel.begin(); it != this->rel.end(); it++){

		// only recognize JUMP_SLOT entries
		if(ELF64_R_TYPE((*it).r_info) != R_X86_64_JUMP_SLOT) continue;
#ifdef DEBUG
		std::cout << "debug:(evalLazy) rel.r_offset: " << (void*)(*it).r_offset
		<< ", relOff: " << (void*)relOff << std::endl;;
#endif
		// if this is the right entry
		if((*it).r_offset == relOff){// || (*it).r_offset == (relOff - 1)){
			this->relocate(&(*it), map);
			return 0;
		}
	}

	for(auto at = this->rela.begin(); at != this->rela.end(); at++){

		// only recognize JUMP_SLOT entries
		if(ELF64_R_TYPE((*at).r_info) != R_X86_64_JUMP_SLOT) continue;
#ifdef DEBUG
		std::cout << "debug:(evalLazy) rel.r_offset: " << (void*)(*at).r_offset
		<< ", relOff: " << (void*)relOff << std::endl;
#endif
		// if this is the right entry (including random matching but skipped previous byte)
		if((*at).r_offset == relOff){// || (*at).r_offset == (relOff - 1)){
			this->relocate(&(*at), map);
			return 0;
		}
	}

#ifdef DEBUG
	// no corresponding entry found
	std::cout << "error:(evalLazy) Couldn't find corresponding rel/rela entry!"
	<< std::endl;
#endif

	return 1;
}


/* Apply all load-time relocations to the loader 
 *
 *  - for every relocation entry
 *      - look up needed symbol in map
 *      - process relocation of the entry
 */
void ElfProcessLoader64::applyLoadRel(std::unordered_map<std::string, RelSym*> *map){

	std::cout << "Applying loadtime relocs to " << getNameFromPath(this->getName())
	<< " ..." << std::endl;
	
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);

	elf->getRelEntries(this->rel);
	elf->getRelaEntries(this->rela);

	SectionInfo dynsymseg = elf->findSectionWithName(".dynsym");
	Elf64_Sym* dynsym = (Elf64_Sym*) dynsymseg.index;

	if(!rel.empty()){
		std::cout << std::dec << rel.size() << " entries in .rel vector."
		<< std::endl;
		for(auto it = std::begin(rel); it != std::end(rel); it++){
			// don't process PLT relocs if bindLazy is set
#ifdef DEBUG
			std::cout << "Rel: [Addr]=" << (void*)it->r_offset
			<< ", [Type]=" << std::dec << ELF64_R_TYPE(it->r_info)
			<< ", [SymbolIdx]=" << ELF64_R_SYM(it->r_info) << std::endl;
#endif
			if(this->bindLazy
				&& (ELF64_R_TYPE((*it).r_info) == R_X86_64_JUMP_SLOT)){
				continue;
			}
			// abort if the current symbol is already defined in this lib
			if(dynsym[ELF64_R_SYM((*it).r_info)].st_shndx != SHN_UNDEF) continue;
			this->relocate(&(*it), map);
		}
	} else { std::cout << "No .rel entries!" << std::endl; }

	if(!rela.empty()){
		std::cout << std::dec << rela.size() << " entries in .rela vector."
		<< std::endl;
		for(auto at = std::begin(rela); at != std::end(rela); at++){
			// don't process PLT relocs if bindLazy is set
#ifdef DEBUG
			std::cout << "Rela: [Addr]=" << (void*)at->r_offset
			<< ", [Type]=" << std::dec << ELF64_R_TYPE(at->r_info)
			<< ", [SymbolIdx]=" << ELF64_R_SYM(at->r_info) << std::endl;
#endif
			if(this->bindLazy
				&& (ELF64_R_TYPE((*at).r_info) == R_X86_64_JUMP_SLOT)){
				continue;
			}

			this->relocate(&(*at), map);
		}
	} else { std::cout << "No .rela entries!" << std::endl; }
}

// TODO maybe write templates instead of second function for rel
/* Process the given relocation entry rel using symbol information from map
 *
 * We only care about relocation entries which correspond to entries in the
 * GOT and PLT, as these are the only locations left to modify before validation.
 * -> R_X86_64_JUMP_SLOT
 * -> R_X86_64_GLOB_DAT
 *
 */
void ElfProcessLoader64::relocate(Elf64_Rela *rel,
								std::unordered_map<std::string, RelSym*> *map){

	uint64_t target; // this is where to make the change in the loader
                     // the address is given as LOCAL address (SHT-VAddr)
	uint64_t value;  // this is the value which gets inserted


	// if .data.rel.ro relocation
	if((ELF64_R_TYPE(rel->r_info) == R_X86_64_RELATIVE)
		|| ELF64_R_TYPE(rel->r_info) == R_X86_64_IRELATIVE){
		/* as this entries are only unique identifiable in their contained
		 * libraries, we only have to stupidly write relative memory addresses
		 * without needing to look up any RelSyms
		 */
#ifdef DEBUG
		std::cout << "debug:(relocate@" << getNameFromPath(this->getName())
		<< ") Found dynamic linking relocation for .data.rel.ro./.got.plt" << std::endl;
#endif

		target = rel->r_offset;

		// sanity check for signed->unsigned conversion
		if(rel->r_addend < 0){
			std::cout << "error:(relocate@" << getNameFromPath(this->getName())
			<< ") Found negative addendum [" << std::hex << rel->r_addend
			<< "] destined for address [" << (void*)target << "]. Skipping."
			<< std::endl;
			return;
		}

		if(ELF64_R_TYPE(rel->r_info) == R_X86_64_RELATIVE){
			value = this->getTextStart() + ((uint64_t)rel->r_addend);
		}
		else{
			if(!this->elffile->isExecutable()) value = this->getTextStart() + ((uint64_t)rel->r_addend);
			else value = (uint64_t)rel->r_addend;
		}

		this->writeRelValue(target, value);
		return;
	}

	// abort if not related to GOT or PLT
	if(ELF64_R_TYPE(rel->r_info) != R_X86_64_JUMP_SLOT
		&& ELF64_R_TYPE(rel->r_info) != R_X86_64_GLOB_DAT
		&& ELF64_R_TYPE(rel->r_info) != R_X86_64_64) return;

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	SectionInfo dynsymseg = elf->findSectionWithName(".dynsym");
	SectionInfo dynstrseg = elf->findSectionWithName(".dynstr");
	Elf64_Sym *dynsym = (Elf64_Sym*) dynsymseg.index;
	char *dynstr = (char*) dynstrseg.index;

	std::string name = &dynstr[dynsym[ELF64_R_SYM(rel->r_info)].st_name];
	RelSym *sym;

	// retrieve needed, corresponding RelSym
	try{
		sym = (*map).at(name);
	} catch (const std::out_of_range& oor){
		std::cout << "error:(relocate) Couldn't retrieve symbol " << name
		<< " from symbolMap! Skipping..." << std::endl;
		return;
	}

	std::cout << "Trying to relocate " << name << " in "
	<< getNameFromPath(this->execName)
	<< " <<-- " << sym->name << " from " 
	<< getNameFromPath(sym->parent->getName()) << "."
	<< std::endl;

	// parse relocation entry
	target = rel->r_offset; // always direct value for JUMP_SLOT/GLOB_DAT
                           // addendum is also not involved in calc
	value = sym->value;

	// write final RelSym address into the corresponding segment
	this->writeRelValue(target, value);
	return;
}

void ElfProcessLoader64::relocate(Elf64_Rel *rel,
								std::unordered_map<std::string, RelSym*> *map){
	std::cout << "Relocation for .rel sections not yet implemented!" << std::endl;
	(void)rel;
	(void)map;
	return;
}

/* Write the given symbol Address (symAddr) into the local field at locAddr
 *
 * In a library locAddr won't refer to a valid vaddr, as the library has most
 * likely been relocated by the dynamic linker. Instead, locAddr refers to
 * a vaddr as specified in the SHT/PHT of the file. We therefore calculate the
 * offset into our dataSection using the vaddr values of the SHT/PHT.
 *
 * locAddr will always point into the dataSection, as we're only processing
 * GOT/PLT relocations.
 */
void ElfProcessLoader64::writeRelValue(uint64_t locAddr, uint64_t symAddr){

	uint64_t offset;  // offset into dataSection
	uint64_t dataVecBaseAddr; // base addr (FILE REPRESENTATION incl padding) of
                              // dataSegVector
	dataVecBaseAddr = (uint64_t) this->dataSegmentInfo.vaddr - 
	                             ((uint64_t) this->dataSegmentInfo.vaddr & 0xfff);

	if(locAddr > dataVecBaseAddr) offset = locAddr - dataVecBaseAddr;
	else{
		std::cout << "error:(writeRelValue) Target address is not in dataSection!"
		<< std::endl << "locAddr = " << (void*)locAddr
		<< ", dataSegmentInfo.vaddr = " << (void*) this->dataSegmentInfo.vaddr << std::endl;
		return;
	}

#ifdef VERBOSE
	std::cout << "Writing " << (void*)symAddr << " at offset " << (void*)offset
	<< " into dataSection. [" << (void*) (locAddr)
	<< "]" << std::endl;
#endif

	// add sizeof(uint64_t) as the address lays after the offset and gets
	// written in the direction of lower addresses

	memcpy(this->dataSectionContent.data() + offset,
			&symAddr, sizeof(symAddr));
	return;
}
