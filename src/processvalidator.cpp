#include <iostream>
#include <iomanip>

#include <cassert>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <unordered_map>
#include <algorithm>

#include <processvalidator.h>

// TODO: retrieve paths from command line parameters
ProcessValidator::ProcessValidator(ElfKernelLoader *kl,
	const std::string binaryName, VMIInstance* vmi, int32_t pid):
		vmi(vmi), kl(kl), pid(pid), tm(){

	std::cout << "ProcessValidator got: " << binaryName << std::endl;

	this->loadExec(binaryName);
	
	std::cout << "Linking VMAs to corresponding Loaders..." << std::endl;
	this->mappedVMAs = tm.getVMAInfo(pid);
	this->buildMaps(this->mappedVMAs);
	this->printVMAs();


	std::vector<VMAInfo> range;
	for (auto section : this->mappedVMAs){
		if(CHECKFLAGS(section.flags, VMAInfo::VM_EXEC)){
			range.push_back(section);
		}
	}

	for (auto line : this->mappedVMAs){
		if(line.flags & VMAInfo::VM_EXEC ||
		    !(line.flags & VMAInfo::VM_WRITE)){
			continue;
		}
		uint64_t counter = 0;
		auto content = vmi->readVectorFromVA(line.start,
		                                    line.end - line.start,
		                                    pid);
		uint8_t* data = content.data();
		for(uint32_t i = 0 ; i < content.size() - 7; i++){
			uint64_t* value = (uint64_t*) data + i;
			//if((*value & 0x00007f00000000UL) != 0x00007f0000000000UL){
			//	continue;
			//}
			for(auto section : range){
				if((CHECKFLAGS(section.flags, VMAInfo::VM_EXEC))){
					if (contained(*value, section.start, section.end)) {
						counter++;
					//std::cout << "Found ptr to: " << section->name << std::endl;
					}
				}
			}
		}

		std::cout << "Found " << COLOR_RED << COLOR_BOLD << 
		    counter << COLOR_RESET << " pointers in section:" << std::endl;
		line.print();
	}


	exit(0);

	//Load trusted executable for checking
	this->lastLoader = this->execLoader;

	// get memindex information

	// adjust the memindex of every library execLoader needs
	std::cout << "Updating memindexes of all libraries..." << std::endl;
	this->updateMemindexes();

	// process load-time relocations
	std::cout << "Processing load-time relocations..." << std::endl;
	this->processLoadRel();
}

ProcessValidator::~ProcessValidator(){}

/* Process load-time relocations of all libraries, which are mapped to the
 * virtual address space of our main process. The following steps have to be
 * taken:
 *
 *  - check which libraries are mapped to the VAS
 *  - generate processing order based on cross-dependencies
 *  - based on the order do for every library:
 *      - retrieve all exported symbols from the respective library
 *      - process relocation of the respective library
 */
void ProcessValidator::processLoadRel(){

	// retrieve mapped libraries in the right order
	std::set<ElfProcessLoader*> mappedLibs = this->getMappedLibs();

	// for every mapped library
	for(auto it : mappedLibs){

		//initialize provided symbols based on updated memindexes
		it->initProvidedSymbols();

		// announce provided symbols
		this->announceSyms(it);

		// process own relocations
		it->applyLoadRel(&this->relSymMap);
	}
	return;
}

/* Gather all libraries which are mapped into the current Address-Space 
 *
 * The dynamic linker has already done the ordering work.
 * The libraries lay in this->mappedVMAs, lowest address first.
 * => Reverse iterate through the mappedVMAs and find the corresponding loader,
 *    gives the loaders in the correct processing order.
 */
std::set<ElfProcessLoader*> ProcessValidator::getMappedLibs(){

	std::set<ElfProcessLoader*> ret;
	ElfProcessLoader* l;

	for(auto it : this->mappedVMAs){

		try{
			l = this->vmaToLoaderMap.at(&it);
		} catch (const std::out_of_range& oor){
#ifdef VERBOSE
			std::cout << "Couldn't find " << it.name << " at "
			<< (void*)it.start
			<< " in vmaToLoaderMap database. Skipping..." << std::endl;
#endif
			continue;
		}

		ret.insert(l);
	}
	return ret;
}

/* Add the symbols, announced by lib, to the nameRelSymMap 
 *
 *  - sweep through all provided symbols of the lib
 *  - if( symbol not yet in map || symbol in map(WEAK) and exported symbol(GLOBAL)
 *      - add to map
 */
void ProcessValidator::announceSyms(ElfProcessLoader* lib){

	std::vector<RelSym*> syms = lib->getProvidedSyms();
	RelSym* match = NULL;

	for(auto it = std::begin(syms); it != std::end(syms); it++){

		try{
			match = this->relSymMap.at((*it)->name);
		} catch (const std::out_of_range& oor){
			// symbol not yet in map -> add
#ifdef VERBOSE
			std::cout << "Adding " << std::setw(40) << std::setfill(' ')
			<< std::left << (*it)->name << "@["
			<< getNameFromPath((*it)->parent->getName()) << "] to relSymMap. "
			<< "[" << (void*)(*it)->value << "]"
			<< std::endl;
#endif
			this->relSymMap[(*it)->name] = (*it);
			continue;
		}

		// symbol already in map -> check if we may overwrite
		if(match != NULL){
			// if mapped symbol is WEAK and cur symbol is GLOBAL -> overwrite
			if(ELF64_ST_BIND(match->info) == STB_WEAK
				&& ELF64_ST_BIND((*it)->info) == STB_GLOBAL){
#ifdef VERBOSE
				std::cout << "Overwriting [WEAK] '" << match->name
				<< "' from " << getNameFromPath(match->parent->getName())
				<< " with [GLOBAL] instance from "
				<< getNameFromPath((*it)->parent->getName()) << "." << std::endl;
#endif
				this->relSymMap[(*it)->name] = (*it);
			}
			match = NULL;
		}
	}
	return;
}


/* Initialize vmaToLoaderMap and addrToLoaderMap  */
void ProcessValidator::buildMaps(std::vector<VMAInfo> vec){

	return;
	std::cout << "Trying to build Maps..." << std::endl;
	//ElfProcessLoader *lib = NULL;

	// for every vma try to find a corresponding Loader
	for(auto it : vec){
		continue;
	}

//		// if main binary
//		if((getNameFromPath(this->execLoader->getName())
//			.compare((*it)->name)) == 0){
//			vmaToLoaderMap.insert(
//				std::pair<VMAInfo*, ElfProcessLoader*>((*it), this->execLoader));
//			addrToLoaderMap.insert(
//				std::pair<uint64_t, ElfProcessLoader*>((*it)->start, 
//															this->execLoader));
//			lib = this->execLoader;
//#ifdef DEBUG
//			std::cout << "Added " << (*it)->name << " to Maps."
//			<< std::endl;
//#endif
//			continue;
//		}

//		// if anon mapping
//		if(it->ino == 0){
//			//Is this the vdso page?
//			if(it->start == this->vdsoLoader->getTextStart()){
//				// add the vdso to the addr->loader map
//#ifdef DEBUG
//				std::cout << "Found VDSO mapping." << std::endl;
//#endif
//				addrToLoaderMap.insert(
//				std::pair<uint64_t, ElfProcessLoader*>(this->vdsoLoader->getTextStart(),
//												this->vdsoLoader));
//			}
//			// if this is a regular anon mapping -> associate with last lib
//			// the mapping will most certainly be the heap of the last lib
//			else{
//				// if this is the stack of our main binary
//				if( it->start >= this->stdStackTop &&
//					it->start <= this->stdStackBot){
//#ifdef DEBUG
//					std::cout << "Found stack of the main binary." << std::endl;
//#endif
//					addrToLoaderMap.insert(
//					std::pair<uint64_t, ElfProcessLoader*>(it->start,
//															this->execLoader));
//				}
//				else{
//					std::string name = getNameFromPath(lib->getName());
//#ifdef DEBUG
//					std::cout << "Found heap of " << name << std::endl;
//#endif
//					addrToLoaderMap.insert(
//						std::pair<uint64_t, ElfProcessLoader*>(it->start, lib));
//					name.append(" <heap>");
//					SectionInfo* heap =
//						new SectionInfo(name, 0, 0, it->start,
//										(it->end - it->start));
//					lib->setHeapSegment(heap);
//				}
//			}
//			continue;
//		}
//
//		// if usual library
//		lib = kl->findLibByName(it->name);
//		if(lib == NULL){
//			assert(lib);
//#ifdef DEBUG
//			std::cout << "error:(buildMaps) Couldn't find corresponding"
//			<< " library for VMA [" << it->name << "]" << std::endl;
//#endif
//			// TODO make sure all libs are here
//			// lib mustn't be NULL for dereferencing in output above
//			lib = this->execLoader;
//		}
//		vmaToLoaderMap.insert(
//			std::pair<VMAInfo*, ElfProcessLoader*>(it, lib));
//		addrToLoaderMap.insert(
//			std::pair<uint64_t, ElfProcessLoader*>(it->start, lib));
//#ifdef DEBUG
//		std::cout << "Added " << it->name << " to Maps."
//		<< std::endl;
//#endif
//	}
}


/* Print the information for all mapped VMAs */
void ProcessValidator::printVMAs(){

	std::cout << "Currently mapped VMAs:" << std::endl;

	int i = 0;
	for(auto it : this->mappedVMAs){
		std::string name;
		if(it.name.compare("") == 0){
			name = "<anonymous>";
		}
		else{
			name = it.name;
		}
		std::cout << "[" << std::right << std::setfill(' ') << std::setw(3)
			<< std::dec << i << "] "
			<< std::left << std::setw(30) << name <<
			std::hex << std::setfill('0')
			<< "0x" << std::right << std::setw(12) << it.start << " - " 
			<< "0x" << std::right << std::setw(12) << it.end << "  "
			<< "0x" << std::right << std::setw(10) << it.off*0x1000
			<< std::setfill(' ') << std::endl;
		i++;
	}
	return;
}


/* Update the memindexes for all loaded libraries */
void ProcessValidator::updateMemindexes(){

	std::string input;
	std::string mapping;

	input = getNameFromPath(this->execLoader->getName());
	mapping = (*std::begin(this->mappedVMAs)).name;
	if(input.compare(mapping) != 0){
		std::cout << "Name of input binary and vma mapping differs! Aborting!"
		<< std::endl
		<< " Input: " << input << ", Mapping: " << mapping << std::endl;
		exit(1);
	}


	ElfProcessLoader *lib = 0;
	uint64_t lastInode = 0;
	uint64_t lastOffset = (uint64_t)-1; // set to greates possible value
//	bool isDataSet = false; // is dataSegment->memindex already set for curLoader
	bool isTextSet = false;

	/* sweep through all VMAs and update the corresponding memindex
	 *
	 * In a virtual address space, vma mappings of libraries are grouped by
	 * their corresponding files/inodes. The first vma mapping of an inode
	 * corresponds to its textSegment, while the mapping with the dataSegBaseOff
	 * of an inode corresponds to its dataSegment.
	 */
	for(auto it : this->mappedVMAs){
#ifdef DEBUG
		std::cout << "Processing entry with start addr " << (void*)it.start
		<< " and inode " << std::dec << it.ino << std::endl;
#endif
		// if the current iterator belongs to the father process
		if(getNameFromPath(this->execLoader->getName()).compare(it.name) == 0){
			// update textSegment?
			// update dataSegment? -> atm only works for PDC
			lib = this->execLoader;
			lastInode = it.ino;
			continue;
		}
		// if the current iterator belongs to the vdso
		else if(this->vdsoLoader->getTextStart() == it.start){
			continue;
		}
		// if the current iterator is a regular library or anon mapping
		else{
			// if anon mapping
			if(it.ino == 0) continue;
			else{
				// if in vm-area of a new loader (inode nrs differ)
				if(lastInode != it.ino){
					lastOffset = (uint64_t)-1;

					// lib++
					try{
						lib = this->vmaToLoaderMap.at(&it);
					} catch (const std::out_of_range& oor){
						std::cout << "Couldn't find mapping starting at "
						<< (void*)it.start
						<< " in library database. Skipping..." << std::endl;
						continue;
					}

					isTextSet = false;
//					isDataSet = false;

					// if the textSegment isn't already set TODO move this back?
					if(!isTextSet){
						if(lib->isTextOffset(it.off * this->stdPageSize)){
							lib->updateMemIndex(it.start, SEG_NR_TEXT);
							isTextSet = true;
						}
					}

					lastInode = it.ino;
				}
				// if still inside same inode area
				else{
					// if dataSegment is not already set
					//if(!isDataSet){
					// if current offset is a data offset and smaller as all before
					if((it.off * this->stdPageSize) < lastOffset){
						// if the current address is the first data address
						if(lib->isDataOffset(it.off * this->stdPageSize)){
							lib->updateMemIndex(it.start, SEG_NR_DATA);
							lastOffset = it.off * this->stdPageSize;
//							isDataSet = true;
						}
					}
					lastInode = it.ino;
					continue;
				}
			}
		}
	}
}

/* If not specified otherwise, reads the first page from heap */
std::vector<uint8_t> ProcessValidator::getHeapContent(VMIInstance *vmi,
														int32_t pid,
														uint32_t readAmount = 0x1000){
	std::vector<uint8_t> heap_content;
	uint64_t heapStart = this->execLoader->getHeapStart();

	std::cout << "Reading first 0x" << std::hex << readAmount << " bytes from"
	<< " heap (" << (void*)heapStart << ") of process " << std::dec << pid
	<< " ... " << std::endl;

	// read heap content from vm
	heap_content = vmi->readVectorFromVA(heapStart, readAmount, pid);
	return heap_content;
}


std::vector<uint8_t> ProcessValidator::getStackContent(VMIInstance *vmi,
														int32_t pid,
														uint32_t offset,
													   uint32_t readAmount=0){

	uint64_t stack_bottom = 0;
	uint64_t stdStackTop = this->stdStackTop; // usual top of stack
	std::vector<uint8_t> stack_content;
	uint64_t startAddr = 0;

	// if ASLR == off, stack always grows down from 0x7ffffffff000 for stat and dyn
	if(offset == 0){
		stack_bottom = this->stdStackBot;
	}
	else{
	// TODO if ASLR is implemented
		stack_bottom = this->stdStackBot + offset;
	}
	if(stack_bottom == 0){
		std::cout << "error: (getProcessEnvironment) could not calculate stack_bottom."
		<< std::endl;
		return stack_content;
	}

	if(readAmount == 0){ // if not specified use default value;
		readAmount = stack_bottom - stdStackTop;
	}
	startAddr = stack_bottom - readAmount;

	std::cout << "Retrieving lower 0x" << std::hex << readAmount
	<< " bytes of stack from process " << std::dec << pid << " ..." << std::endl;

	// get stack content from VM
	stack_content = vmi->readVectorFromVA(startAddr, readAmount, pid);

	return stack_content;
}


void ProcessValidator::getProcessEnvironment(VMIInstance *vmi, int32_t pid, uint32_t offset){

	std::vector<std::string> temp; // buffer for environ
	std::vector<uint8_t> stack_content;
	uint32_t readAmount = 0x1000; // 0x1000 bytes should be way enough to contain
								  // all environment variables
	std::string marker = "x86_64"; // marker, on stack on top of environment variables
	uint8_t matching = 0;    // amount of matching marker bytes
	std::string stringBuf = ""; // buffer for extracting 'var=value'

	// get stack part, containing env
	stack_content = this->getStackContent(vmi, pid, offset, readAmount);

	uint32_t varBegin = 0;

	// get position of environ
	for(uint32_t i = 0; i < stack_content.size(); i++){
		switch(matching){
			case 0:
						if(stack_content[i] == 'x'){
							matching++;
						} else { matching = 0;}
						continue;
			case 1:
						if(stack_content[i] == '8'){
							matching++;
						} else { matching = 0;}
						continue;
			case 2:
						if(stack_content[i] == '6'){
							matching++;
						} else { matching = 0;}
						continue;
			case 3:
						if(stack_content[i] == '_'){
							matching++;
						} else { matching = 0;}
						continue;
			case 4:
						if(stack_content[i] == '6'){
							matching++;
						} else { matching = 0;}
						continue; 
			case 5:
						if(stack_content[i] == '4'){
							varBegin = i+2;
							break;
						} else {matching = 0;}
						continue;
		}
		if(matching == 5) break;
	}


	if(varBegin == 0){
		std::cout << "error: (getProcessEnvironment) couldn't find marker "
		<< marker <<  std::endl;
		return;
	}


	// parse variables from stack_content
	for(; varBegin < stack_content.size(); varBegin++){
		if(stack_content[varBegin] == 0x0){
				temp.push_back(stringBuf);
				stringBuf = "";
		}
		else{
			stringBuf.push_back(stack_content[varBegin]);
		}
	}

	int len;

	// remove everything non-variable
	for(auto it = temp.begin(); it != temp.end(); it++){
		// if no '=' is in the current string, ignore it.
		len = (*it).find('=');
		if(((*it).find('=') != std::string::npos)
			&& ((*it)[0] >= 65)
			&& ((*it)[0] <= 90)){
			this->envMap.insert(std::pair<std::string, std::string>(
								(*it).substr(0, len),
								(*it).substr(len+1, std::string::npos)));
		}
	}


#ifdef DEBUG
	std::cout << "debug: (getProcessEnvironment) Parsed env-vars. Content:" << std::endl;
	for ( auto var : this->envMap){
		std::cout << var.first << "\t" << var.second << std::endl;
	}

#endif
}

int ProcessValidator::checkEnvironment(std::map<std::string, std::string> inputMap){

	int errors = 0;
	std::string value;


	// check all input settings
	for(auto inputPair : inputMap){
		try{
			// get env value for current input key
			value = this->envMap.at(inputPair.first);
		}
		catch (const std::out_of_range& oor) {
			// TODO : This behaviour only validates, if variable is set. maybe change
			// no such entry in our environ -> variable not set -> no threat
			// -> check next input setting
#ifdef DEBUG
			std::cout << "debug: (checkEnvironment) no entry " << inputPair.first
			<< " in envMap." << std::endl;
#endif
			continue;
		}
		if(value.compare(inputPair.second) == 0){
			// setting is right
#ifdef DEBUG
			std::cout << "debug: (checkEnvironment) entry " << inputPair.first
			<< " in envMap has the correct value " << inputPair.second << std::endl;
#endif
		continue;
		}
		else{
			// setting is wrong 
			errors++;
			std::cout
#ifndef DUMP
			<< COLOR_RED
#endif
			<< "Found mismatch in environment variables on entry " << inputPair.first
			<< ". Expected: '" << inputPair.second << "', found: '"
			<< value << "'. Errors: " << errors
#ifndef DUMP
			<< COLOR_NORM
#endif
			<< std::endl;
		}
	}
	return errors;
}


/* Find a corresponding ElfProcessLoader for the given vaddr
 *
 * By providing a backup loader, this function guarantees to return a valid
 * loader, if no entry in the database is found.
 */
ElfProcessLoader* ProcessValidator::getLoaderForAddress(uint64_t addr,
                                                        ElfProcessLoader* backup){

	ElfProcessLoader *ret = NULL;
	try{
		ret = this->addrToLoaderMap.at(addr);
	} catch (const std::out_of_range& oor){
#ifdef DEBUG
		std::cout << "Couldn't find corresponding match to " << (void*)addr
		<< " in addr->loader map. Defaulting to last loader..." << std::endl;
#endif
		ret = backup;
	}
	return ret;
}

/* Find a corresponding SectionInfo for the given vaddr */
SectionInfo* ProcessValidator::getSegmentForAddress(uint64_t vaddr){

	SectionInfo *ret;

	// find a corresponding loader for the given vaddr
	ElfProcessLoader* loader = this->getLoaderForAddress(vaddr, this->lastLoader);
	this->lastLoader = loader;
	ret = loader->getSegmentForAddress(vaddr);
	return ret;
}

/* Lazy evaluation of the given address addr
 *
 *   - get corresponding loader/segment for addr
 *   - if ( addr subject to LazyBinding )
 *       - relocate the address
 *       - return 0
 *   - else
 *       - return 1
 */
int ProcessValidator::evalLazy(uint64_t start, uint64_t addr){

	ElfProcessLoader* loader = 0;

	try{
		loader = this->addrToLoaderMap.at(start);
	} catch (const std::out_of_range& oor){
#ifdef DEBUG
		std::cout << "debug:(evalLazy) Couldn't find a corresponding loader "
		<< "for address " << (void*)addr << std::endl;
		return 1;
#endif
	}

//	std::cout << "loader: " << (void*)loader << std::endl;

	return loader->evalLazy(addr, &this->relSymMap);
}

int ProcessValidator::_validatePage(page_info_t *page, int32_t pid){
	assert(page);

	// TODO optimize this output, such that we don't have to check for stack
	// address here everytime
	if(page->vaddr >= this->stdStackTop && page->vaddr <= this->stdStackBot){
		std::cout << "Located in stack of "
		<< getNameFromPath(this->execLoader->getName()) << std::endl;
		return 0;
	}

	SectionInfo *targetSegment = this->getSegmentForAddress(page->vaddr);

	if(targetSegment == NULL){
		std::cout << "Located in heap." << std::endl;
		return 0;
	}

	// check if the targetSegment is a heapSegment (might check name cont. heap)
//	if(targetSegment->index == 0 && targetSegment->segID == 0){
	if(targetSegment->segName.find("<heap>") != std::string::npos){
		std::cout << "Located in heap of " << targetSegment->segName
		<< ". Skipping..." << std::endl;
		return 0;
	}
	else{
		std::cout << "Located in " << getNameFromPath(this->lastLoader->getName())
		<< std::endl;
	}


#ifdef DEBUG
	std::cout << "debug: checking page 0x" << std::hex << page->vaddr << std::endl;
#endif

	//TODO: Check what happens, if offset is negative (maybe replace by int64_t
	uint64_t pageOffset = 0; // offset of page to actual aligned memindex of the
                             // containing segment
//#ifdef DEBUG
	uint64_t pageIndex = 0;  // offset above in amount of pages (index)
//#endif
	uint32_t changeCount = 0; // Number of differing bytes in validation process

#ifdef DEBUG
	printf("debug: page->vaddr:0x%lx, memindex=0x%lx\n", page->vaddr, (uint64_t) targetSegment->memindex);
#endif

	pageOffset = (page->vaddr - 
				 ((uint64_t) targetSegment->memindex)); //& 0xffffffffffff ));
	pageIndex = (page->vaddr - 
				 ((uint64_t) targetSegment->memindex)// & 0xffffffffffff )
				) / page->size;

#ifdef DEBUG
	std::cout << "debug: Initialized pageOffset=0x" << pageOffset << ", pageIndex=0x"
			  << pageIndex << std::endl;
#endif

	std::cout << "pageOffset: " << (void*) pageOffset
	<< ", pageIndex: " << (void*) pageIndex << std::endl;


	// get Page from exec
    // check if the loaded procimage already contains the page we just retrieved
	if(targetSegment->size < pageOffset){
		//This section is not completely loaded
		assert(false);
	}
    // the corresponding page out of our procimage
	uint8_t *loadedPage = targetSegment->index + pageOffset;
//	uint8_t* loadedPage = (execLoader->getImageForAddress(page->vaddr, pageOffset));
					//	execLoader->textSegmentContent.data() + pageOffset;
	if(loadedPage == NULL) return 1;


	// get Page _content_ from VM
	std::vector<uint8_t> pageInMem =
						 vmi->readVectorFromVA(page->vaddr, page->size, pid);

#ifdef DEBUG
	std::cout << "Content of the whitelisted page:" << std::endl;
    std::vector<uint8_t> dummy;
    dummy.insert(std::begin(dummy), loadedPage, (loadedPage + 0x1000));
    printHexDump(&dummy);

    std::cout << "Content of the page in memory:" << std::endl;
    printHexDump(&pageInMem);
/*	for(auto it = std::begin(pageInMem); it != std::end(pageInMem); it++){
		printf("%c", *it);
	}
*/
#endif


	// lazy evaluation lock
	// TODO maybe optimize, only search for lazyBinding entry every 8 bytes?
	uint8_t remain = 0;

	// check byte for byte
	for(int32_t i = 0; i < page->size; i++){

		if(loadedPage[i] == pageInMem[i]){
#ifdef DEBUG
	#ifndef DUMP
			std::cout << COLOR_GREEN << "Address "<< COLOR_BOLD <<  std::hex
					  << (void*) (page->vaddr+i) << COLOR_BOLD_OFF << " is fine."
					  << std::endl << COLOR_NORM;
	#endif
	#ifdef DUMP
			std::cout << "Address 0x" << std::hex << (int)(page->vaddr+i)
					  << " is fine." << std::endl;
	#endif
#endif
			if(remain > 0) remain--;
			continue;
		}
		else{

			// if we have _not_ written recently due to lazyEval we may write
			if(remain == 0){
				// Lazy Evaluation TODO this can be optimized by giving the targetSegment->index directly
				if(!this->evalLazy((uint64_t)targetSegment->memindex,
									((uint64_t)targetSegment->memindex) + i + pageOffset)){
					// Lazy evaluation has been applied. Block the next 8 Bytes
					// from writing!
					remain = 7;
#ifdef DEBUG
					std::cout << "Found change. remain: " << std::hex << (int)remain << std::endl;
#endif
					if(loadedPage[i] == pageInMem[i]){
#ifdef DEBUG
	#ifndef DUMP
						std::cout << COLOR_GREEN << "Address "<< COLOR_BOLD <<  std::hex
							  << (void*) (page->vaddr+i) << COLOR_BOLD_OFF << " is fine."
							  << " [Evaluated Lazy]"
							  << std::endl << COLOR_NORM;
	#endif
	#ifdef DUMP
						std::cout << "Address 0x" << std::hex << (int)(page->vaddr+i)
							  << " is fine. [Evaluated Lazy]" << std::endl;
	#endif
#endif
						continue;
					}
				}
			}
			// if we have written recently, the error should be resolved or malicious
			else{
				remain--;
			}

			changeCount++;
#ifndef DUMP
			std::cout << COLOR_RED << "Found mutation at " << COLOR_BOLD
					  << std::hex << (void*)(i+page->vaddr)
					  << COLOR_BOLD_OFF << ". Expected:'" << COLOR_BOLD << "0x"
					  << std::setfill('0') << std::setw(2) << (int)(loadedPage[i])
					  << COLOR_BOLD_OFF << "', found:'" << COLOR_BOLD << "0x"
					  << std::setw(2) << (int)(pageInMem[i]) << COLOR_BOLD_OFF
					  << "'. Errors = " << std::dec <<  changeCount << COLOR_NORM << std::endl;
#endif
#ifdef DUMP
			std::cout << "Found mutation at " << std::hex << (void*)(i+page->vaddr)
					  << ". Expected:'" << "0x" << std::setfill('0') << std::setw(2)
					  << (int)(loadedPage[i]) << "', found:'" << "0x" << std::setw(2)
					  << (int)(pageInMem[i]) << "'. Change count = " << std::dec
					  << changeCount << std::endl;
#endif
		}
	}

	if(changeCount == 0) std::cout << "Page fine." << std::endl;

	return changeCount;
}


int ProcessValidator::validatePage(page_info_t *page, int32_t pid){

#ifndef DUMP
	std::cout << std::setfill('-') << std::setw(80) << "" << COLOR_YELLOW << std::endl
			  << "Verifying page.\nVirtual Address: "<< COLOR_BOLD << "0x" << std::hex << page->vaddr << COLOR_BOLD_OFF
			  << "\nPhysical Address: 0x" << std::hex << page->paddr << std::endl
			  << COLOR_NORM;
#endif
#ifdef DUMP
	std::cout << std::setfill('-') << std::setw(80) << "" << std::endl
			  << "Verifying page.\nVirtual Address: " << "0x" << std::hex << page->vaddr
			  << "\nPhysical Address: 0x" << std::hex << page->paddr << std::endl;
#endif


/* OBSOLETE
	// Try to find a corresponding whitelisted executable for the page
	//TODO fix this, atm points to segment after textSegment

	ElfLoader *corrExec;

	corrExec = this->execLoader->getExecForAddress(page->vaddr);

	if(corrExec == NULL){
		std::cout << "error: (validatePage) No corresponding file found for address " << std::hex
                  << (void*) page->vaddr << std::endl;
		return 1;
	}
	else{
		// check (W xor X) policy
		if (corrExec->isDataAddress(page->vaddr)){
			if(this->vmi->isPageExecutable(page)){
				std::cout << COLOR_RED  << "Warning: Executable _AND_ writable page found at "
				<< COLOR_BOLD << (void*) page->vaddr << COLOR_BOLD_OFF
				<< COLOR_NORM << std::endl;
			}
		}
*/
	return this->_validatePage(page, pid);
//	}
//	return 0;
}

int ProcessValidator::loadExec(const std::string path){
	
	//Create ELF Object
	ElfFile *execFile = ElfFile::loadElfFile(path);

	std::string name = path.substr(path.rfind("/", std::string::npos) + 1,
	                               std::string::npos);
	this->execLoader = dynamic_cast<ElfProcessLoader64 *>
               (execFile->parseElf(ElfFile::ELFPROGRAMTYPEEXEC, name, kl));
	this->execLoader->parseElfFile();

	return 0;
}

