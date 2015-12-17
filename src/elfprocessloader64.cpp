#include "elfprocessloader64.h"

ElfProcessLoader64::ElfProcessLoader64(ElfFile64 *file,
                                       Kernel *kernel,
                                       const std::string &name)
	:
	ElfProcessLoader(file, kernel, name),
	bindLazy(true) {
}

ElfProcessLoader64::~ElfProcessLoader64() {
}

/* Return the final memory address in the procImg for the given addr
 *
 *  - get the offset from file start for the address
 *  - translate the offset in an offset into text/dataSection
 *  - return text/dataSection->memindex + segOffset
 *
 */
uint64_t ElfProcessLoader64::getVAForAddr(uint64_t addr, uint32_t shtID) {
	UNUSED(addr);
	UNUSED(shtID);
	assert(false);
	return 0;
//	ElfFile64 *elf = dynamic_cast<ElfFile64 *>(this->elffile);
//	uint64_t off   = elf->elf64Shdr[shtID].sh_offset;  // offset to cont. section
//	// offset to symbol address from section start
//	uint64_t symOff = addr - elf->elf64Shdr[shtID].sh_addr;
//	uint64_t va     = 0;
//
//	if (this->isTextOffset(off)) {
//		va = (((uint64_t) this->textSegment.memindex) + off + symOff);
//	} else if (this->isDataOffset(off)) {
//		va = (((uint64_t) this->dataSection.memindex) +
//		      (off - this->dataSegmentInfo.offset)  // offset into dataSection
//		      +
//		      symOff);  // offset to target symbol
//	} else {
//		std::cout << "error:(getVAForAddr) Couldn't find VA for addr "
//		          << (void *)addr << ", offset " << (void *)off << " in SHT ["
//		          << std::dec << shtID << "]. "
//		          << "Returning dataSection..." << std::endl;
//		return (uint64_t) this->dataSection.memindex;
//	}
//
//	return va;
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
int ElfProcessLoader64::evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym> *map) {
	// TODO XXX applyRelocations und evalLazy geht noch nicht
	// Die Relocations müssen noch von dem Kommentar unten in die
	// ElfFile Klasse portiert werden.
	UNUSED(addr);
	UNUSED(map);
	return -1;
}


/*
int ElfProcessLoader64::evalLazy(uint64_t addr, std::unordered_map<std::string, RelSym *> *map) {
	std::string debug;

	// if the entry should've already been processed
	if (this->bindLazy == false)
		return 1;

	uint64_t off = 0;  // offset of symbol into corresponding segment (independent)
	uint64_t relOff = 0;  // r_offset which should correspond to the right rel/a entry
	// FILE REPRESENTATION!
	uint64_t dataVecBaseAddr;  // starting address (FILE REPRESENTATION) of data
	                           // vector content (including padding)

	if (this->isCodeAddress(addr)) {
		off   = addr - ((uint64_t) this->textSegment.memindex);
		debug = "code";
	} else if (this->isDataAddress(addr)) {
		off   = addr - ((uint64_t) this->dataSection.memindex);
		debug = "data";
	} else {
		std::cout << "error:(evalLazy@" << getNameFromPath(this->execName)
		          << ") Given addr " << (void *)addr
		          << " is not contained in any segment!" << std::endl
		          << "off: " << (void *)off << ", relOff: " << (void *)relOff
		          << std::endl;
		return 1;
	}
	// recognize textSeg padding from last page border
	dataVecBaseAddr = (uint64_t) this->dataSegmentInfo.vaddr -
	                  ((uint64_t) this->dataSegmentInfo.vaddr & 0xfff);
	relOff = off + dataVecBaseAddr;
#ifdef DEBUG
	std::cout << "debug:(evalLazy) addr = " << (void *)addr << ", offset into "
	          << debug << " segment " << (void *)off << std::endl;
#endif
	// find corresponding rel/rela entry
	for (auto &it : this->rel) {
		// only recognize JUMP_SLOT entries
		if (ELF64_R_TYPE(it.r_info) != R_X86_64_JUMP_SLOT)
			continue;
#ifdef DEBUG
		std::cout << "debug:(evalLazy) rel.r_offset: " << (void *)it.r_offset
		          << ", relOff: " << (void *)relOff << std::endl;
		;
#endif
		// if this is the right entry
		if (it.r_offset == relOff) {  // || (*it).r_offset == (relOff - 1)){
			this->relocate(&it, map);
			return 0;
		}
	}

	for (auto &at : this->rela) {
		// only recognize JUMP_SLOT entries
		if (ELF64_R_TYPE(at.r_info) != R_X86_64_JUMP_SLOT)
			continue;
#ifdef DEBUG
		std::cout << "debug:(evalLazy) rel.r_offset: " << (void *)at.r_offset
		          << ", relOff: " << (void *)relOff << std::endl;
#endif
		// if this is the right entry (including random matching but skipped
		// previous byte)
		if (at.r_offset == relOff) {  // || (*at).r_offset == (relOff - 1)){
			this->relocate(&at, map);
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
*/

/* Apply all load-time relocations to the loader
 *
 *  - for every relocation entry
 *      - look up needed symbol in map
 *      - process relocation of the entry
 */
void ElfProcessLoader64::applyLoadRel(ProcessValidator *val) {
	// TODO XXX TOM
	// Das kompiliert noch nicht. Die applyRelocations muss noch für den
	// ProcessLoader angepasst werden
	UNUSED(val);
	// this->elffile->applyRelocations(this);
}

/*
void ElfProcessLoader64::applyLoadRel(std::unordered_map<std::string, RelSym *> *map) {

	std::cout << "Applying loadtime relocs to "
	          << getNameFromPath(this->getName()) << " ..." << std::endl;

	ElfFile64 *elf = dynamic_cast<ElfFile64 *>(this->elffile);

	elf->getRelEntries(this->rel);
	elf->getRelaEntries(this->rela);

	SectionInfo dynsymseg = elf->findSectionWithName(".dynsym");
	Elf64_Sym *dynsym     = (Elf64_Sym *)dynsymseg.index;

	if (!rel.empty()) {
		std::cout << std::dec << rel.size() << " entries in .rel vector."
		          << std::endl;
		for (auto &it : rel) {
			// don't process PLT relocs if bindLazy is set
#ifdef DEBUG
			std::cout << "Rel: [Addr]=" << (void *)it->r_offset
			          << ", [Type]=" << std::dec << ELF64_R_TYPE(it->r_info)
			          << ", [SymbolIdx]=" << ELF64_R_SYM(it->r_info)
			          << std::endl;
#endif
			if (this->bindLazy &&
			    (ELF64_R_TYPE(it.r_info) == R_X86_64_JUMP_SLOT)) {
				continue;
			}
			// abort if the current symbol is already defined in this lib
			if (dynsym[ELF64_R_SYM(it.r_info)].st_shndx != SHN_UNDEF)
				continue;
			this->relocate(&it, map);
		}
	} else {
		std::cout << "No .rel entries!" << std::endl;
	}

	if (!rela.empty()) {
		std::cout << std::dec << rela.size() << " entries in .rela vector."
		          << std::endl;
		for (auto &at : rela) {
			// don't process PLT relocs if bindLazy is set
#ifdef DEBUG
			std::cout << "Rela: [Addr]=" << (void *)at->r_offset
			          << ", [Type]=" << std::dec << ELF64_R_TYPE(at->r_info)
			          << ", [SymbolIdx]=" << ELF64_R_SYM(at->r_info)
			          << std::endl;
#endif
			if (this->bindLazy &&
			    (ELF64_R_TYPE(at.r_info) == R_X86_64_JUMP_SLOT)) {
				continue;
			}

			this->relocate(&at, map);
		}
	} else {
		std::cout << "No .rela entries!" << std::endl;
	}
}
*/

// TODO maybe write templates instead of second function for rel
/* Process the given relocation entry rel using symbol information from map
 *
 * We only care about relocation entries which correspond to entries in the
 * GOT and PLT, as these are the only locations left to modify before
 * validation.
 * -> R_X86_64_JUMP_SLOT
 * -> R_X86_64_GLOB_DAT
 *
 */
void ElfProcessLoader64::relocate(Elf64_Rela *rel) {
	UNUSED(rel);
	assert(false);
	return;
//	uint64_t target;  // this is where to make the change in the loader
//	                  // the address is given as LOCAL address (SHT-VAddr)
//	uint64_t value;   // this is the value which gets inserted
//
//	// abort if not related to GOT or PLT
//	if (ELF64_R_TYPE(rel->r_info) != R_X86_64_JUMP_SLOT &&
//	    ELF64_R_TYPE(rel->r_info) != R_X86_64_GLOB_DAT &&
//	    ELF64_R_TYPE(rel->r_info) != R_X86_64_64) {
//		return;
//	}
//
//	// if .data.rel.ro relocation
//	if (ELF64_R_TYPE(rel->r_info) == R_X86_64_RELATIVE ||
//	    ELF64_R_TYPE(rel->r_info) == R_X86_64_IRELATIVE) {
//
//		/* as this entries are only unique identifiable in their contained
//		 * libraries, we only have to stupidly write relative memory addresses
//		 * without needing to look up any RelSyms
//		 */
//
//		target = rel->r_offset;
//
//		// sanity check for signed->unsigned conversion
//		assert(rel->r_addend >= 0);
//
//		if (ELF64_R_TYPE(rel->r_info) == R_X86_64_RELATIVE) {
//			value = this->getTextStart() + ((uint64_t)rel->r_addend);
//		} else {
//			if (!this->elffile->isExecutable())
//				value = this->getTextStart() + ((uint64_t)rel->r_addend);
//			else
//				value = (uint64_t)rel->r_addend;
//		}
//
//		this->writeRelValue(target, value);
//		return;
//	}
//
//	ElfFile64 *elf        = dynamic_cast<ElfFile64 *>(this->elffile);
//	SectionInfo dynsymseg = elf->findSectionWithName(".dynsym");
//	SectionInfo dynstrseg = elf->findSectionWithName(".dynstr");
//	Elf64_Sym *dynsym     = (Elf64_Sym *)dynsymseg.index;
//	char *dynstr          = (char *)dynstrseg.index;
//
//	std::string name = &dynstr[dynsym[ELF64_R_SYM(rel->r_info)].st_name];
//	// XXX TODO make that shit better!
//	return;
//	//RelSym *sym = this->proc->findSymbolByName(name);
//
//	//// retrieve needed, corresponding RelSym
//	//if (!sym) {
//	//	std::cout << "error:(relocate) Couldn't retrieve symbol " << name
//	//	          << " from symbolMap! Skipping..." << std::endl;
//	//	return;
//	//}
//
//	//std::cout << "Trying to relocate " << name << " in "
//	//          << this->name << " <<-- " << sym->name
//	//          << "." << std::endl;
//
//	//// parse relocation entry
//	//target = rel->r_offset;  // always direct value for JUMP_SLOT/GLOB_DAT
//	//                         // addendum is also not involved in calc
//	//value = sym->value;
//
//	//// write final RelSym address into the corresponding segment
//	//this->writeRelValue(target, value);
//	//return;
}

void ElfProcessLoader64::relocate(Elf64_Rel *rel) {
	std::cout << COLOR_RED << COLOR_BOLD
	          << "Relocation for .rel sections not yet implemented!"
	          << COLOR_RESET << std::endl;
	UNUSED(rel);
	assert(false);
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
void ElfProcessLoader64::writeRelValue(uint64_t locAddr, uint64_t symAddr) {
	UNUSED(locAddr);
	UNUSED(symAddr);
	assert(false);
	return;
//	uint64_t offset;  // offset into dataSection
//	uint64_t
//	dataVecBaseAddr;  // base addr (FILE REPRESENTATION incl padding) of
//	// dataSegVector
//	dataVecBaseAddr = (uint64_t) this->dataSegmentInfo.vaddr -
//	                  ((uint64_t) this->dataSegmentInfo.vaddr & 0xfff);
//
//	if (locAddr > dataVecBaseAddr)
//		offset = locAddr - dataVecBaseAddr;
//	else {
//		std::cout
//		<< "error:(writeRelValue) Target address is not in dataSection!"
//		<< std::endl
//		<< "locAddr = " << (void *)locAddr << ", dataSegmentInfo.vaddr = "
//		<< (void *)this->dataSegmentInfo.vaddr << std::endl;
//		return;
//	}
//
//#ifdef VERBOSE
//	std::cout << "Writing " << (void *)symAddr << " at offset "
//	          << (void *)offset << " into dataSection. [" << (void *)(locAddr)
//	          << "]" << std::endl;
//#endif
//
//	// add sizeof(uint64_t) as the address lays after the offset and gets
//	// written in the direction of lower addresses
//
//	memcpy(this->dataSegmentContent.data() + offset, &symAddr, sizeof(symAddr));
//	return;
}
