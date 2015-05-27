#include "elfprocessloader64.h"

RelSym::RelSym(std::string name, uint64_t value, uint8_t info, uint32_t shndx,
				ElfProcessLoader64* parent):
		name(name), value(value), info(info), shndx(shndx), parent(parent){}

RelSym::~RelSym(){}


ElfProcessLoader64::ElfProcessLoader64(ElfFile64 *file, std::string name)
									   : ElfProcessLoader(file, name),
										 bindLazy(true), isDynamicExec(false),
										 isInLibs(false), isRelocatable(false),
										 dataSegBaseAddr(0), textSegBaseAddr(0),
										 dataSegPHTid(0), textSegPHTid(0),
										 dataSegSHTid(0), textSegSHTid(0),
										 pageSize(0x1000) {
	this->execName = name;
#ifdef DEBUG
	std::cout << "ElfProcessLoader64 initialized!" << std::endl;
#endif
}

ElfProcessLoader64::~ElfProcessLoader64(){}

/* Beginning body of the loader */

void ElfProcessLoader64::setIsLib(bool isLib){
	this->isInLibs = isLib;
}

/* Get the vmem address of the first memory segment */
uint64_t ElfProcessLoader64::getTextStart(){
	return (uint64_t) this->textSegment.memindex;
}

uint64_t ElfProcessLoader64::getDataStart(){
	return (uint64_t) this->dataSegment.memindex;
}

/* Get the vmem address of the corresponding VDSO */
uint64_t ElfProcessLoader64::getVDSOAddr(){
	return this->vdsoAddr;
}

/* Return the name of the contained executable */
std::string ElfProcessLoader64::getName(){
	return this->execName;
}

/* Return the beginning of the heap */
uint64_t ElfProcessLoader64::getHeapStart(){

	// heap starts after last data page
	// if size not page aligned
	uint16_t offset = 0;
	if((this->dataSegment.size % 0x1000) != 0x0){
		offset = this->pageSize - ((uint64_t)this->dataSegment.size & 0xfff);
	}

	uint64_t heapStart = (uint64_t)this->dataSegment.memindex
							+ this->dataSegment.size
							+ offset;
	return heapStart;
}

/* Get the size of the dataSegment */
uint32_t ElfProcessLoader64::getDataSize(){
	return this->dataSegment.size;
}
/* Get the size of the textSegment */
uint32_t ElfProcessLoader64::getTextSize(){
	return this->textSegment.size;
}

/* Get reference to the suppliedLibraries */
std::vector<ElfProcessLoader64*>* ElfProcessLoader64::getLibraries(){
	return this->suppliedLibraries;
}

std::vector<RelSym*> ElfProcessLoader64::getProvidedSyms(){
	return this->providedSyms;
}

std::vector<std::string> ElfProcessLoader64::getDepNames(){
	return this->depNames;
}

/* Init the names of all needed libraries in this loader */
void ElfProcessLoader64::initDepNames(){


	// if this is a static exec we don't have any dependencies
	if(!this->isDynamicExec) return;

	// get .dynamic section
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	SegmentInfo dynamic = elf->findSegmentWithName(".dynamic");
	SegmentInfo dynstr = elf->findSegmentWithName(".dynstr");
	Elf64_Dyn *dynamicEntries = (Elf64_Dyn*)(dynamic.index);
	char *strtab = (char*)(dynstr.index);
	std::string buf;

#ifdef VERBOSE
	std::cout << this->execName << " needs the following libraries:" << std::endl;
#endif
	for(int i = 0; (dynamicEntries[i].d_tag != DT_NULL); i++){
		if(dynamicEntries[i].d_tag == DT_NEEDED){
			// insert name from symbol table on which the d_val is pointing
			buf.append(&strtab[(dynamicEntries[i].d_un.d_val)]);
			this->depNames.push_back(buf);
#ifdef VERBOSE
			std::cout << this->depNames.back() << std::endl;
#endif
			buf = "";
		}
		if(dynamicEntries[i].d_tag == DT_BIND_NOW){
			this->bindLazy = false;
		}
	}
	return;
}

/* Supply heap information to the Loader */
void ElfProcessLoader64::setHeapSegment(SegmentInfo* heap){
	this->heapSegment = *heap;
	this->heapSegmentLength = this->heapSegment.size;
}


/*
 * For relocatable objects: Update the memindex value [defining where this .so
 * is located in the calling process' address space].
 */
void ElfProcessLoader64::updateMemIndex(uint64_t addr, uint8_t segNr){

	std::string section;
	SegmentInfo *seg;
	switch(segNr){ // extendable with Macros in util.h

		case SEG_NR_DATA:
				seg = &this->dataSegment;
				section = "data";
				break;
		case SEG_NR_TEXT:
		default:
				seg = &this->textSegment;
				section = "text";
				break;
	}

	if(isInLibs){
#ifdef DEBUG
		std::cout << "debug: Library " << getNameFromPath(this->execName)
		<< " is updating ["
		<< section << "] memindex (" << std::hex
		<< (void*) seg->memindex << ") to " << (void*) addr << std::endl;
#endif
		seg->memindex = (uint8_t*) addr;

		if(this->memImageVDSO == this){
#ifdef DEBUG
			std::cout << "debug: as this is our vdso vdsoAddr is now also set." << std::endl;
#endif
			this->vdsoAddr = addr;
		}
	}
}

/* Check if the given virtual address is located in the textSegment */
bool ElfProcessLoader64::isCodeAddress(uint64_t addr){
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);

	// get offset to last page border
	uint64_t endAddr = ((uint64_t)this->textSegment.memindex)
						+(elf->elf64Phdr[this->textSegPHTid].p_offset & 0xfff)
						+ elf->elf64Phdr[this->textSegPHTid].p_memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if(addr >= ((uint64_t)this->textSegment.memindex)
		&& addr < (endAddr + offset)){ 
		return true;
	}
	else return false;
}


/* Check if the given virtual address is located in the dataSegment */
bool ElfProcessLoader64::isDataAddress(uint64_t addr){
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);

	// get offset to last page border
	uint64_t endAddr = ((uint64_t)this->dataSegment.memindex)
						+(elf->elf64Phdr[this->dataSegPHTid].p_offset & 0xfff)
						+ elf->elf64Phdr[this->dataSegPHTid].p_memsz;
	// off = 0x1000 - (endAddr & 0xfff)
	uint64_t offset = 0x1000 - (endAddr & 0xfff);

	if(addr >= ((uint64_t)this->dataSegment.memindex)
		&& addr < (endAddr + offset)){ 
		return true;
	}
	else return false;
}

/* Check if the given fileOffset (in bytes) lays in the textSegment */
bool ElfProcessLoader64::isTextOffset(uint64_t off){
	uint64_t pagedDataOff = (this->dataSegBaseOff
								- (this->dataSegBaseOff & 0xfff));
	if(off >= this->textSegBaseOff && off < pagedDataOff) return true;
	else return false;
}

/* Check if the given fileOffset (in bytes) lays in the dataSegment */
bool ElfProcessLoader64::isDataOffset(uint64_t off){
	uint64_t pagedDataOff = (this->dataSegBaseOff
								- (this->dataSegBaseOff & 0xfff));
	if(off >= pagedDataOff) return true;
	else return false;
}


uint64_t ElfProcessLoader64::getDataOff(){
	return this->dataSegBaseOff;
}

uint64_t ElfProcessLoader64::getTextOff(){
	return this->textSegBaseOff;
}

/* Check if the given library is in this->suppliedLibraries */
bool ElfProcessLoader64::isInLibraries(ElfProcessLoader64 *lib){
	for(auto it = this->suppliedLibraries->begin();
				it != this->suppliedLibraries->end(); it++){
		if(lib == (*it)){
			return true;
		}
	}
	return false;
}


bool ElfProcessLoader64::isDynamic(){
	return this->isDynamicExec;
}

/* Check if the current file is a relocatable object */
void ElfProcessLoader64::initIsRelocatable(){

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	Elf64_Ehdr* hdr = (Elf64_Ehdr*) elf->getFileContent();
	if(hdr->e_type == ET_REL) this->isRelocatable = false;
	else this->isRelocatable = true;
	return;
}


/* Check if the current File is statically linked */
void ElfProcessLoader64::initIsDynamic(){

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int nrSecHeaders = elf->getNrOfSections();
	
	for(int i = 0; i < nrSecHeaders; i++){

		this->textSegment = elf->findSegmentByID(i);
		if(this->textSegment.segName.compare(".dynamic") == 0){
#ifdef DEBUG
			std::cout << "Found .dynamic section. [" << std::dec << i << "]" << std::endl;
#endif
			this->isDynamicExec = true;
			return;
		}
	}

	this->isDynamicExec = false;
#ifdef DEBUG
	std::cout << "No .dynamic section found, processing static binary." << std::endl;
#endif
}


/* Append the stated memory segment to the given image */
uint32_t ElfProcessLoader64::appendSegToImage(SegmentInfo *segment,
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
	std::cout << "Content of the current dataSegment (" << this->execName
	<< "):" << std::endl;
	printHexDump(&(this->dataSegmentContent));	

/*
	for(auto it = std::begin(textSegmentContent); it != std::end(textSegmentContent); it++){
		printf("%c", *it);
	}
*/
}

/* Append arbitrary data from pointer to given image */
uint32_t ElfProcessLoader64::appendDataToImage(const void *data, uint32_t len,
                                               std::vector<uint8_t> *target){
	uint8_t *input = (uint8_t*) data;
	target->insert(target->end(), input, (input + len));
	return len;
}

/* Return a reference to the loader inheriting the given addr */
ElfProcessLoader64* ElfProcessLoader64::getExecForAddress(uint64_t addr){

#ifdef DEBUG
	std::cout << "debug: Asked for Exec. My memindex is " << (void*) this->textSegment.memindex
			  << std::endl << "debug: memindex of my vdso is "
			  << (void*) this->memImageVDSO->getStartAddr() << std::endl
			  << "debug: memindex of my dataSegment is "
			  << (void*) this->dataSegment.memindex << std::endl;
#endif

	if((addr >= (uint64_t) this->textSegment.memindex
       && addr < (uint64_t) (this->textSegment.memindex + this->textSegment.size))
			||
		(addr >= (uint64_t) this->dataSegment.memindex
		&& addr < (uint64_t) (this->dataSegment.memindex + this->dataSegment.size))
			||
		(addr >= this->vdsoAddr
		&& addr < (this->vdsoAddr + this->memImageVDSO->getTextSize()))){

#ifdef DEBUG
		std::cout << "Returning " << this->execName << " for addr=0x"
			  << std::hex << addr << std::endl;
#endif
		return this; 
	}

	//TODO experimental. Check if still works!
	/*
	ElfProcessLoader64 *lib = NULL;
	// sweep through all direct dependencies TODO optimize (map?)
	for(auto it = this->depNames.begin(); it != this->depNames.end(); it++){
		lib = ProcessValidator::getLibByName((*it));
		if(((addr >= (uint64_t)lib->getTextStart())
			&& addr < (uint64_t)(lib->getTextStart() + lib->getTextSize()))
			||
			((addr >= (uint64_t)lib->getDataStart())
			&& (addr < (uint64_t)(lib->getDataStart() + lib->getDataSize())))
		  ){
			std::cout << "Returning " << lib->getName() << " for addr=0x"
			<< std::hex << addr << std::endl;
			return lib;
		}
	}
	*/
#ifdef DEBUG
	std::cout << "debug: Given address " << std::hex << (void*) addr
	<< " is not contained in " << this->execName << " and dependencies! Aborting..." << std::endl;
#endif
	return NULL;
}

/* Return the SegmentInfo, in which the given addr is contained. */
SegmentInfo* ElfProcessLoader64::getSegmentForAddress(uint64_t addr){

	// check textSegment
	if(addr >= (uint64_t) this->textSegment.memindex &&
				addr < ((uint64_t)this->textSegment.memindex) + this->textSegment.size){
		return &this->textSegment;
#ifdef DEBUG
		std::cout << "debug: (getSegmentForAddress) in " << this->execName
		<< " Returning textSegmentInfo for addr "
		<< std::hex << (void*) addr << std::endl;
#endif
	}
	// check dataSegment
	else if(addr >= (uint64_t)this->dataSegment.memindex &&
			addr < ((uint64_t)(this->dataSegment.memindex) + this->dataSegment.size)){
#ifdef DEBUG
		std::cout << "debug: (getSegmentForAddress) in " << this->execName 
		<< " Returning dataSegment for addr "
		<< std::hex << (void*) addr << std::endl;
#endif
		return &this->dataSegment;
	}
	// check heapSegment
	else if(addr >= (uint64_t)this->heapSegment.memindex &&
			addr <= (uint64_t)(this->heapSegment.memindex + this->heapSegment.size)){
#ifdef DEBUG
		std::cout << "debug: (getSegmentForAddress) in " << this->execName 
		<< " Returning heapSegment for addr "
		<< std::hex << (void*) addr << std::endl;
#endif
		return &this->heapSegment;
	}

/*	// check vdso OBSOLETE by ProcessValidator::addr->loaderMap
	else if(addr >= this->vdsoAddr &&
			addr < (this->vdsoAddr + this->memImageVDSO->getTextSize())){
#ifdef DEBUG
		std::cout << "debug: (getSegmentForAddress) in " << this->execName 
		<< " requesting value from VDSO for addr "
		<< std::hex << (void*) addr << std::endl;
#endif
	return this->memImageVDSO->getSegmentForAddress(addr);
	}
*/
/*
	// check all dependencies TODO
	uint64_t curDepMemindex = dependency.getCurMemindex();
	else if(

*/
	else{
/*		std::cout << "No SegmentInfo in "
		<< this->execName << " containing "
		<< std::hex << (void*) addr << ". Located in heap." << std::endl;*/
		return NULL;
	}
}

/* Add the specified sections to the given memory Segment
 *
 * If invoking, set prevMemAddr = $(Start address of memory segment)
 *                  prevSecSize = 0
 *
 * for working offset initalization
 */
void ElfProcessLoader64::addSectionsToSeg(ElfFile64 *elf, int nrSecHeaders,
                                          int prevMemAddr, int prevSecSize,
                                          uint64_t startAddr, uint64_t endAddr,
                                          SegmentInfo *handler,
                                          std::vector<uint8_t> *target,
                                          uint32_t *targetLength){
    int id = 0;
    uint32_t offset = 0;
	std::string strtarget;

	if(target == &this->textSegmentContent) strtarget = "Text";
	if(target == &this->dataSegmentContent) strtarget = "Data";

	// add all sections below endAddr to the target Segment
	for(id = 0; id < nrSecHeaders; id++){

        uint32_t flags = elf->elf64Shdr[id].sh_flags;
		if(((flags & SHF_ALLOC) == SHF_ALLOC)){ 

			*handler = elf->findSegmentByID(id);



			// if the current processed segment is .bss, and were processing the 
			// dataSegment, fill with 0x0 until page border
			if(handler->segName.compare(".bss") == 0 && target == &this->dataSegmentContent){
#ifdef VERBOSE
				std::cout << "Found .bss section. Filling with 0x0 until next page border..."
				<< std::endl;
#endif
				uint64_t bssStart = (uint64_t) elf->elf64Shdr[id].sh_offset;
				uint64_t offsetToBorder = this->pageSize - (bssStart & 0xfff);
				std::vector<uint8_t> zeroes;
				zeroes.assign(offsetToBorder, 0x0);
				this->dataSegmentLength += appendDataToImage(zeroes.data(),
															 offsetToBorder,
															 &this->dataSegmentContent);
				prevMemAddr = elf->elf64Shdr[id].sh_addr;
				prevSecSize = elf->elf64Shdr[id].sh_size;
				return;
			}

			// if the current segment is _not_ .bss but has type NOBITS (e.g. .tbss)
			// simply ignore it and don't add any bytes to the image
			if(elf->elf64Shdr[id].sh_type == SHT_NOBITS){
				continue;
			}


            if((elf->elf64Shdr[id].sh_addr < endAddr && elf->elf64Shdr[id].sh_addr >= startAddr)){

    			offset = elf->elf64Shdr[id].sh_addr - (prevMemAddr + prevSecSize);
#ifdef DEBUG
    			std::cout << "debug: offset = 0x" << std::hex << offset << std::endl;
    			if(offset != 0){
    				std::cout << "Offset of 0x" << std::hex << offset << " bytes "
                              << "found before " << handler->segName
                              << std::endl;
			    }
#endif
#ifdef VERBOSE
		    	std::cout << "Adding section [" << std::dec << id << "] " << handler->segName
                << " to " << strtarget <<"-Segment at 0x" << std::hex << (*targetLength)
                << " + 0x" << (int)offset << std::endl;
#endif
				(*targetLength) += this->appendSegToImage(handler,
                                                              target,
                                                              offset);
#ifdef DEBUG
				std::cout << "debug: targetLength=" << std::hex << (*targetLength)
						  << std::endl;
#endif
				prevMemAddr = elf->elf64Shdr[id].sh_addr;
				prevSecSize = elf->elf64Shdr[id].sh_size;
			}
		}
	}
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
 *	boundary, containing information from the dataSegment.
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

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int nrSecHeaders = elf->getNrOfSections();
	this->textSegmentLength = 0;
    uint64_t prevMemAddr = 0; // for inter-section offset calculation
	int prevSecSize = 0; // memsize of previous section

	// if this is a vdso, we just stupidly copy everything from the memimage
	// into the vector
	if(this->memImageVDSO == this){
#ifdef DEBUG
		std::cout << "debug: Found vdso. Loading image into textSegment." << std::endl;
#endif
		this->textSegment.segName = (elf->getFilename()).append(".textSegment");
		this->textSegment.segID = 0;
		this->textSegment.index = elf->getFileContent();
		this->textSegment.memindex = (uint8_t*) this->vdsoAddr;
		this->textSegment.size = elf->getFileSize();

		this->textSegmentContent.insert(std::begin(this->textSegmentContent),
                                        this->textSegment.index,
                                        this->textSegment.index + this->textSegment.size);
		this->textSegmentLength = this->textSegment.size;
		return;
	}


	// find dataSegment and textSegment Base addresses in PHDRTBL
	for(int i = 0; i < elf->elf64Ehdr->e_phnum; i++){
		if(elf->elf64Phdr[i].p_type == PT_LOAD){
			if(elf->elf64Phdr[i].p_flags == (PF_W | PF_R) ||
               elf->elf64Phdr[i].p_flags == PF_R){
				this->dataSegBaseAddr = elf->elf64Phdr[i].p_vaddr;
				this->dataSegBaseOff = elf->elf64Phdr[i].p_offset;
				this->dataSegPHTid = i;
			}
			if(elf->elf64Phdr[i].p_flags == (PF_X | PF_R)){
				prevMemAddr = elf->elf64Phdr[i].p_vaddr; // init with ELF-Header addr
				prevSecSize = elf->elf64Ehdr->e_ehsize;
                this->textSegBaseAddr = elf->elf64Phdr[i].p_vaddr;
				this->textSegBaseOff = elf->elf64Phdr[i].p_offset;
				this->textSegPHTid = i;
			}
		}
	}

	// get SHTid of first section in dataSegment
	for(int i = 0; i < nrSecHeaders; i++){
		if(elf->elf64Shdr[i].sh_addr == this->dataSegBaseAddr
			&& this->dataSegSHTid == 0){
#ifdef DEBUG
			std::cout << "debug: First section in dataSegment has SHTid="
			<< (int)i << std::endl;
#endif		// only set this, if it is not already set
			// bug: .tbss gets ignored -> wrong page ending insert (overflow)
			this->dataSegSHTid = i;
		}
		if(elf->elf64Shdr[i].sh_addr == this->textSegBaseAddr){
#ifdef DEBUG
			std::cout << "debug: First section in textSegment has SHTid="
			<< (int)i << std::endl;
#endif
			this->textSegSHTid = i;
		}
	}

	if(this->dataSegSHTid == 0){
			std::cout << "ERROR: ID of first data section not found!" << std::endl;
	}



    // for elf-files without dataSegment to load (e.g. vdso), init address to end of textSegment
    if(this->dataSegBaseAddr == 0) this->dataSegBaseAddr = 
                                    elf->elf64Phdr[this->textSegPHTid].p_vaddr
                                   +elf->elf64Phdr[this->textSegPHTid].p_memsz;

#ifdef DEBUG
	std::cout << "debug: textSegBaseAddr=0x" << std::hex << this->textSegBaseAddr << std::endl
			  << "debug: dataSegBaseAddr=0x" << std::hex << this->dataSegBaseAddr << std::endl
			  << "debug: prevMemAddr=0x" << std::hex << prevMemAddr << std::endl;
#endif

	// add ELF-Header (maybe move later)
#ifdef DEBUG
	std::cout << "debug: Trying to add ELF-Header..." << std::endl;
#endif
	this->textSegmentLength += this->appendDataToImage(elf->elf64Ehdr,
                                                       elf->elf64Ehdr->e_ehsize,
                                                       &(this->textSegmentContent));

	// add PHDRTBL (maybe move later)
#ifdef DEBUG
	std::cout << "debug:Trying to add Program Header Table..." << std::endl;
#endif
	this->textSegmentLength += this->appendDataToImage(elf->elf64Phdr,
                                                       (elf->elf64Ehdr->e_phentsize*
                                                       elf->elf64Ehdr->e_phnum),
                                                       &(this->textSegmentContent));
	prevSecSize = 0; //dirty init for working inter-section offsets
	prevMemAddr = elf->elf64Shdr[1].sh_addr;

    // add all sections in the text segment of the ELF-File to textSegmentContent
    this->addSectionsToSeg(elf, nrSecHeaders, prevMemAddr, prevSecSize,
                           this->textSegBaseAddr, this->dataSegBaseAddr,
                           &(this->textSegment), &(this->textSegmentContent),
                           &(this->textSegmentLength));

	/*
	 * If this is a dynamic linked binary, clear the space after the last added
	 * section (set to 0x0) unitl the page boundary (0x1000) and (depending) 
	 * add first bytes from dataSegment at corresponding address
	 */
	if(this->isDynamicExec){
#ifdef DEBUG
		std::cout << "Found dynamic exec, clearing ending of textSegment and "
		<< "merging with dataSegment border..." << std::endl;
#endif

	//stupidly write bytes from dataSegment until page border is reached.

		uint64_t startWrite = elf->elf64Shdr[this->dataSegSHTid-1].sh_offset + 
				elf->elf64Shdr[this->dataSegSHTid-1].sh_size;
		uint64_t zeroLine = elf->elf64Shdr[this->dataSegSHTid].sh_offset;
		uint64_t endWrite = (this->pageSize);
		uint32_t len = endWrite - (zeroLine & 0xfff);
		uint8_t *fileContent = elf->getFileContent();
		this->textSegmentContent.insert(std::end(this->textSegmentContent),
										zeroLine-startWrite, 0x0);
		this->textSegmentLength += (zeroLine-startWrite);
		this->textSegmentLength += appendDataToImage(fileContent + zeroLine, len, &this->textSegmentContent);
	}

	/* 
	 * Update this->textSegment to match an actual memory segment from PHT
	 * rather than a section. After this, this->textSegment can be used for
	 * handling the memory segment (e.g. by the ProcessValidator).
	 */
	this->textSegment.segName = (elf->getFilename()).append(".textSegment");
	this->textSegment.segID = this->textSegPHTid;
	this->textSegment.index = this->textSegmentContent.data();
	this->textSegment.memindex = (uint8_t*) elf->elf64Phdr[this->textSegPHTid].p_vaddr;
	this->textSegment.size = this->textSegmentLength;

	// check alignment (p_vaddr - p_offset % p_align == 0)
	auto entryPoint =  elf->elf64Phdr[this->textSegPHTid].p_vaddr - elf->elf64Phdr[textSegPHTid].p_offset;
	if( entryPoint % elf->elf64Phdr[this->textSegPHTid].p_align != 0){
		std::cout << "error: alignment of PHDR broken!" << std::endl
		<< "p_vaddr: " << (elf->elf64Phdr[this->textSegPHTid].p_vaddr)
		<< " || offset: " << elf->elf64Phdr[this->textSegPHTid].p_offset
		<< " || p_align: " << elf->elf64Phdr[this->textSegPHTid].p_align << std::endl;

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

#ifdef DEBUG
	std::cout << "debug: initializing dataSegment of " << this->execName << std::endl;
#endif

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int nrSecHeaders = elf->getNrOfSections();
	this->dataSegmentLength = 0;
    uint64_t prevMemAddr = 0; // for inter-section offset calculation
	int prevSecSize = 0; // memsize of previous section
	uint64_t endAddr = 0;


	// if this is a VDSO do nothing
	if(this->memImageVDSO == this) return;


	// calculate endAddr of dataSegment. PHTids should be set by now [initText].
	endAddr = elf->elf64Phdr[this->dataSegPHTid].p_vaddr
              + elf->elf64Phdr[this->dataSegPHTid].p_memsz;


	/* insert page padding from text segment */

	uint8_t *fileContent = this->elffile->getFileContent();
	// get actual starting point of data
	uint64_t dataLine = elf->elf64Shdr[dataSegSHTid].sh_offset;
	// get the starting point of the information to include from text
	uint64_t pageStart = dataLine - (dataLine & (0xfff));
	// insert everything between
	this->dataSegmentLength += this->appendDataToImage(fileContent + pageStart,
														(dataLine - pageStart),
														&this->dataSegmentContent);

#ifdef DEBUG
	std::cout << "debug: (initData) init endAddr=" << std::hex <<  (void*)endAddr << std::endl;
#endif


	// add regular sections contained in the dataSegment
	prevMemAddr = elf->elf64Shdr[dataSegSHTid].sh_addr;
	this->addSectionsToSeg(elf, nrSecHeaders, prevMemAddr, prevSecSize,
                           this->dataSegBaseAddr, endAddr,
                           &(this->dataSegment), &(this->dataSegmentContent),
                           &(this->dataSegmentLength));


    // Update this->dataSegment to match an actual memory segment.
    this->dataSegment.segName = (elf->getFilename()).append(".dataSegment");
	this->dataSegment.segID = this->dataSegPHTid;
	this->dataSegment.index = this->dataSegmentContent.data();
// next value is obsolete if page alignment is taken into account
//	this->dataSegment.memindex = (uint8_t*) elf->elf64Phdr[this->dataSegPHTid].p_vaddr;
	this->dataSegment.size = this->dataSegmentLength; // TODO is this already page-aligned?
	
	// page alignment and sanity check
	uint64_t align =  elf->elf64Phdr[this->dataSegPHTid].p_vaddr - elf->elf64Phdr[this->dataSegPHTid].p_offset;
	if( align % elf->elf64Phdr[this->dataSegPHTid].p_align != 0){
			std::cout << "error: alignment of PHDR broken!" << std::endl
			<< "p_vaddr: " << (elf->elf64Phdr[this->dataSegPHTid].p_vaddr)
			<< " || offset: " << elf->elf64Phdr[this->dataSegPHTid].p_offset
			<< " || p_align: " << elf->elf64Phdr[this->dataSegPHTid].p_align << std::endl;
		}
	else{ // if the alignment values are correct
		//determine the correct page-aligned memindex (p_vaddr - (p_offset & 0xfff)).
			uint64_t entryPoint = (elf->elf64Phdr[this->dataSegPHTid].p_vaddr
									- (elf->elf64Phdr[this->dataSegPHTid].p_offset & 0xfff));
#ifdef DEBUG
			std::cout << "debug: new page aligned memindex for dataSegment would be: "
			<< std::hex << (void*)entryPoint << std::endl;
#endif
			this->dataSegment.memindex = (uint8_t*) entryPoint;
		}

	/* Clean Up */

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
	if(!this->isDynamic()) return;

	std::cout << "Initializing provided symbols of " << getNameFromPath(this->execName)
	<< " ..." << std::endl;

	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	SegmentInfo dynamic = elf->findSegmentWithName(".dynamic");
	// use symtab instead of dynsym?
	SegmentInfo symtab = elf->findSegmentWithName(".dynsym"); 
	SegmentInfo strtab = elf->findSegmentWithName(".dynstr");

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
 *  - translate the offset in an offset into text/dataSegment
 *  - return text/dataSegment->memindex + segOffset
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
		va = (((uint64_t)this->dataSegment.memindex)
				+ (off - this->dataSegBaseOff) // offset into dataSegment
				+ symOff);                     // offset to target symbol
	}
	else{
		std::cout << "error:(getVAForAddr) Couldn't find VA for addr "
		<< (void*) addr << ", offset "
		<< (void*)off << " in SHT [" << std::dec << shtID << "]. "
		<< "Returning dataSegment..." << std::endl;
		return (uint64_t)this->dataSegment.memindex;
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
		off = addr - ((uint64_t)this->dataSegment.memindex);
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
	dataVecBaseAddr = this->dataSegBaseAddr - (this->dataSegBaseAddr & 0xfff);
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

	this->rel = this->getRelEntries();
	this->rela = this->getRelaEntries();

	ElfFile64* elf = dynamic_cast<ElfFile64*>(this->elffile);
	SegmentInfo dynsymseg = elf->findSegmentWithName(".dynsym");
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

/* Return all relocation entries from all .rel sections
 *
 *  - find .rel sections (if any)
 *  - build vector from entries
 */
std::vector<Elf64_Rel> ElfProcessLoader64::getRelEntries(){

	std::vector<Elf64_Rel> ret;
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int maxSec = elf->getNrOfSections();
	int nrRel = 0;
	SegmentInfo relseg;

	// find .rel sections
	for(int i = 0; i < maxSec; i++){
		if(elf->elf64Shdr[i].sh_type == SHT_REL){
			relseg = elf->findSegmentByID(i);
			nrRel = (int)(elf->elf64Shdr[i].sh_size / sizeof(Elf64_Rel));
			// add .rel entries to vector
			for(int j = 0; j < nrRel; j++){
				ret.push_back(((Elf64_Rel*)relseg.index)[j]);
			}
		}
	}
	return ret;
}

/* Return all relocation entries from all .rela sections
 *
 *  - find .rela sections (if any)
 *  - build vector from entries
 */
std::vector<Elf64_Rela> ElfProcessLoader64::getRelaEntries(){

	std::vector<Elf64_Rela> ret;
	ElfFile64 *elf = dynamic_cast<ElfFile64*>(this->elffile);
	int maxSec = elf->getNrOfSections();
	int nrRela = 0;
	SegmentInfo relseg;

	// find .rela sections
	for(int i = 0; i < maxSec; i++){
		if(elf->elf64Shdr[i].sh_type == SHT_RELA){
			relseg = elf->findSegmentByID(i);
			nrRela = (int)(elf->elf64Shdr[i].sh_size / sizeof(Elf64_Rela));
			// add .rela entries to vector
			for(int j = 0; j < nrRela; j++){
				ret.push_back(((Elf64_Rela*)relseg.index)[j]);
			}
		}
	}
	return ret;
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
			if(this->isInLibs) value = this->getTextStart() + ((uint64_t)rel->r_addend);
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
	SegmentInfo dynsymseg = elf->findSegmentWithName(".dynsym");
	SegmentInfo dynstrseg = elf->findSegmentWithName(".dynstr");
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
 * offset into our dataSegment using the vaddr values of the SHT/PHT.
 *
 * locAddr will always point into the dataSegment, as we're only processing
 * GOT/PLT relocations.
 */
void ElfProcessLoader64::writeRelValue(uint64_t locAddr, uint64_t symAddr){

	uint64_t offset;  // offset into dataSegment
	uint64_t dataVecBaseAddr; // base addr (FILE REPRESENTATION incl padding) of
                              // dataSegVector
	dataVecBaseAddr = this->dataSegBaseAddr - (this->dataSegBaseAddr & 0xfff);

	if(locAddr > dataVecBaseAddr) offset = locAddr - dataVecBaseAddr;
	else{
		std::cout << "error:(writeRelValue) Target address is not in dataSegment!"
		<< std::endl << "locAddr = " << (void*)locAddr
		<< ", dataSegBaseAddr = " << (void*) this->dataSegBaseAddr << std::endl;
		return;
	}

#ifdef VERBOSE
	std::cout << "Writing " << (void*)symAddr << " at offset " << (void*)offset
	<< " into dataSegment. [" << (void*) (locAddr)
	<< "]" << std::endl;
#endif

	// add sizeof(uint64_t) as the address lays after the offset and gets
	// written in the direction of lower addresses

	memcpy(this->dataSegmentContent.data() + offset,
			&symAddr, sizeof(symAddr));
	return;
}


void ElfProcessLoader64::supplyVDSO(ElfProcessLoader64 *vdso){
	this->memImageVDSO = vdso;
}

void ElfProcessLoader64::supplyLibraries(std::vector<ElfProcessLoader64*> *libs){
	this->suppliedLibraries = libs;
}


/* Initialize a complete memory image for validation. Relocations are not yet processed */
void ElfProcessLoader64::parseElfFile(){
	std::cout << std::setfill('-') << std::setw(80) << "" << std::endl;
	std::cout << "Building process image from file: " << getNameFromPath(this->execName)
			  << std::endl;

	/*
	 * this may only be executed, if this is NOT a vdso or lib. Set the addr to vdso
	 * depending on linking type of calling exec..
	 */
	if(this->memImageVDSO != this){
		this->initIsDynamic(); //TODO optimize, avoid 2nd run through sections 
#ifdef DEBUG
		std::cout << "debug: initDynamic complete. current bin is " << this->isDynamicExec << std::endl
        << std::endl;
#endif
		if(this->isDynamicExec == true){
			this->vdsoAddr = 0x7ffff7ffa000; //TODO make this magic nrs abstract (libvmi info?) 
		}
		else{
			this->vdsoAddr = 0x7ffff7ffd000;
		}
	}

	// set isRelocatable member
	this->initIsRelocatable();

	// init the first memory segment
	this->initText();
	// init the second memeory segment
	this->initData();

#ifdef DEBUG
	printf("debug: meminit=%lx\ndebug: this=%p, this->memImageVDSO=%p\n",
			(uint64_t)this->textSegment.memindex, this, this->memImageVDSO);
#endif
	// init the names of all dependency libraries
	this->initDepNames();
}


