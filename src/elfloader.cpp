#include "elfloader.h"


namespace kernint {

ElfLoader::ElfLoader(ElfFile *elffile)
	:
	elffile(elffile) {

#ifdef DEBUG
	std::cout << "Trying to initialize ElfLoader..." << std::endl;
#endif
}


void ElfLoader::initImage() {
	this->initText();
	this->initData();
}

bool ElfLoader::isCodeAddress(uint64_t addr) {
	addr = addr | 0xffff000000000000;
	return this->textSegment.containsMemAddress(addr);
}

const std::vector<uint8_t> &ElfLoader::getTextSegment() const {
	return this->textSegmentContent;
}

const std::vector<uint8_t> &ElfLoader::getDataSegment() const {
	return this->dataSegmentContent;
}

} // namespace kernint
