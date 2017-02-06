#include "processvalidator.h"

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <iostream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unordered_map>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "elffile.h"
#include "elfkernelloader.h"
#include "elfuserspaceloader.h"
#include "taskmanager.h"


namespace kernint {

class PagePtrInfo {
public:

PagePtrInfo(Process* process, const VMAInfo *fromVMA, const VMAInfo &toVMA)
	:
	count{0},
	ptrs{},
	process{process},
	data{nullptr},
	fromVMA{fromVMA},
	toVMA{toVMA} {

	if (fromVMA->name[0] != '[') {
		this->fromLoader = this->process->findLoaderByFileName(fromVMA->name);
	} else {
		this->fromLoader = this->process->getExecLoader();
	}
	this->toLoader = this->process->findLoaderByFileName(toVMA.name);

	if (this->toLoader != nullptr) {
		this->data = this->toLoader->getTextSegment().data();
	}
}

~PagePtrInfo() = default;

uint32_t getCount() {
	return count;
}

void addPtr(uint64_t where, uint64_t addr) {
	this->count += 1;
	this->ptrs[addr].insert(where);
}

typedef enum {
	PTR_NO_SECTION      = 1 << 0,
	PTR_PLAIN_FILE      = 1 << 1,
	PTR_SECTION_START   = 1 << 2,
	PTR_DYNSTR          = 1 << 3,
	PTR_DYNSYM          = 1 << 4,
	PTR_SEC_NOT_TEXT    = 1 << 5,
	PTR_SYMBOL          = 1 << 6,
	PTR_ENTRY           = 1 << 7,
	PTR_INVALID_INSTR   = 1 << 8,
	PTR_UNINT_INSTR     = 1 << 9,
	PTR_RETURN          = 1 << 10,
	PTR_UNKNOWN         = 1 << 12,
	PTR_GADGET          = 1 << 13,
	PTR_NOT_7f          = 1 << 14,
	PTR_UNINT_INSTR_NC  = 1 << 15,
	PTR_END_PRINTABLE   = 1 << 16
} ptr_class_e;

static std::string printStat2(std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> ptr_class) {
	size_t overall              = 0;
	size_t overall_not_7f       = 0;
	size_t overall_7f           = 0;
	size_t ptr_unique            = 0;
	size_t ptr_unique_not_7f     = 0;
	size_t ptr_unique_7f         = 0;
	size_t ptr_text             = 0;
	size_t ptr_text_not_7f      = 0;
	size_t ptr_text_7f          = 0;
	size_t ptr_unk              = 0;
	size_t ptr_unk_not_7f       = 0;
	size_t ptr_unk_7f           = 0;
	size_t ptr_inv_inst         = 0;
	size_t ptr_inv_inst_not_7f  = 0;
	size_t ptr_inv_inst_7f      = 0;
	size_t ptr_unin_inst        = 0;
	size_t ptr_unin_inst_not_7f = 0;
	size_t ptr_unin_inst_7f     = 0;
	size_t ptr_unin_ret         = 0;
	size_t ptr_unin_ret_not_7f  = 0;
	size_t ptr_unin_ret_7f      = 0;
	size_t ptr_unin_gad        = 0;
	size_t ptr_unin_gad_not_7f = 0;
	size_t ptr_unin_gad_7f     = 0;
	size_t ptr_unk_print        = 0;
	size_t ptr_unk_print_not_7f = 0;
	size_t ptr_unk_print_7f     = 0;

	for (auto && ptr : ptr_class) {
		auto flags = ptr.second.second;
		
		overall += ptr.second.first;
		ptr_unique++;
		if(!(CHECKFLAGS(flags, PTR_SEC_NOT_TEXT))) ptr_text++;
		if(CHECKFLAGS(flags, PTR_UNKNOWN)) ptr_unk++;
		if(CHECKFLAGS(flags, PTR_INVALID_INSTR)) ptr_inv_inst++;
		if(CHECKFLAGS(flags, PTR_UNINT_INSTR)) ptr_unin_inst++;
		if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_RETURN))) ptr_unin_ret++;
		if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_GADGET))) ptr_unin_gad++;
		if(CHECKFLAGS(flags, (PTR_UNKNOWN | PTR_END_PRINTABLE))) ptr_unk_print++;


		if(CHECKFLAGS(flags, PTR_NOT_7f)){
			overall_not_7f += ptr.second.first;
			ptr_unique_not_7f++;
			if(!(CHECKFLAGS(flags, PTR_SEC_NOT_TEXT))) ptr_text_not_7f++;
			if(CHECKFLAGS(flags, PTR_UNKNOWN)) ptr_unk_not_7f++;
			if(CHECKFLAGS(flags, PTR_INVALID_INSTR)) ptr_inv_inst_not_7f++;
			if(CHECKFLAGS(flags, PTR_UNINT_INSTR)) ptr_unin_inst_not_7f++;
			if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_RETURN))) ptr_unin_ret_not_7f++;
			if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_GADGET))) ptr_unin_gad_not_7f++;
			if(CHECKFLAGS(flags, (PTR_UNKNOWN | PTR_END_PRINTABLE))) ptr_unk_print_not_7f++;
		}else{
			overall_7f += ptr.second.first;
			ptr_unique_7f++;
			if(!(CHECKFLAGS(flags, PTR_SEC_NOT_TEXT))) ptr_text_7f++;
			if(CHECKFLAGS(flags, PTR_UNKNOWN)) ptr_unk_7f++;
			if(CHECKFLAGS(flags, PTR_INVALID_INSTR)) ptr_inv_inst_7f++;
			if(CHECKFLAGS(flags, PTR_UNINT_INSTR)) ptr_unin_inst_7f++;
			if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_RETURN))) ptr_unin_ret_7f++;
			if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_GADGET))) ptr_unin_gad_7f++;
			if(CHECKFLAGS(flags, (PTR_UNKNOWN | PTR_END_PRINTABLE))) ptr_unk_print_7f++;
		}
	}

	//   << "Overall ptrs;"
	//   << "Unique ptrs;"
	//   << "Not PIE;"
	//   << "Ptr Known;"
	//   << "No corresponding section;"
	//   << "Ptr to plain file;"
	//   << "Ptr to start of section;"
	//   << "Pointer to Section != .text;"
	//   << "Ptr to String (.dynstr);"
	//   << "Ptr to Symbol (.dynsym)";
	//   << "Pointer to Symbol;"
	//   << "Pointer to EntryPoint;"
	//   << "Return Address;"
	//   << "Unknown Ptr;"
	//   << "Unknown Ptr Pie;"
	//   << "Unknown Pie End Printable"
	//   << "Invalid Instruction;"
	//   << "Unintended Instruction;"
	//   << "Unintended Instruction not checked;"
	//   << "Unintended Return instruction;"
	//   << "Unintended Usable Gadget;"

	std::stringstream ss;
	ss << ";" << overall       << " (" << overall_7f << " / " << overall_not_7f << ")"
	   << ";" << ptr_unique    << " (" << ptr_unique_7f << " / " << ptr_unique_not_7f << ")"
	   << ";" << ptr_text      << " (" << ptr_text_7f << " / " << ptr_text_not_7f << ")"
	   << ";" << ptr_unk       << " (" << ptr_unk_7f << " / " << ptr_unk_not_7f << ")"
	   << ";" << ptr_unk_print << " (" << ptr_unk_print_7f << " / " << ptr_unk_print_not_7f << ")"
	   << ";" << ptr_inv_inst  << " (" << ptr_inv_inst_7f << " / " << ptr_inv_inst_not_7f << ")"
	   << ";" << ptr_unin_inst << " (" << ptr_unin_inst_7f << " / " << ptr_unin_inst_not_7f << ")"
	   << ";" << ptr_unin_ret  << " (" << ptr_unin_ret_7f << " / " << ptr_unin_ret_not_7f << ")"
	   << ";" << ptr_unin_gad  << " (" << ptr_unin_gad_7f << " / " << ptr_unin_gad_not_7f << ")"
	;

	return ss.str();
}

static std::string printStat(std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> ptr_class, bool count_not_7f = true) {
	size_t overall              = 0;
	size_t ptr_not_7f           = 0;
	size_t ptr_unk_7f           = 0;
	size_t ptr_no_section       = 0;
	size_t ptr_plain_file       = 0;
	size_t ptr_section_start    = 0;
	size_t ptr_dynstr           = 0;
	size_t ptr_dynsym           = 0;
	size_t ptr_sec_not_text     = 0;
	size_t ptr_symbol           = 0;
	size_t ptr_entry            = 0;
	size_t ptr_invalid_instr    = 0;
	size_t ptr_unint_instr      = 0;
	size_t ptr_unint_instr_nc   = 0;
	size_t ptr_return           = 0;
	size_t ptr_unint_return     = 0;
	size_t ptr_unknown          = 0;
	size_t ptr_unint_gadget     = 0;
	size_t ptr_unk_7f_end_print = 0;

	for (auto && ptr : ptr_class) {
		if(!count_not_7f && !(ptr.first >> 24)) continue;
		overall += ptr.second.first;
		auto flags = ptr.second.second;
		if(CHECKFLAGS(flags, PTR_NO_SECTION)) ptr_no_section++;
		if(CHECKFLAGS(flags, PTR_PLAIN_FILE)) ptr_plain_file++;
		if(CHECKFLAGS(flags, PTR_SECTION_START)) ptr_section_start++;
		if(CHECKFLAGS(flags, PTR_DYNSTR)) ptr_dynstr++;
		if(CHECKFLAGS(flags, PTR_DYNSYM)) ptr_dynsym++;
		if(CHECKFLAGS(flags, PTR_SEC_NOT_TEXT)) ptr_sec_not_text++;
		if(CHECKFLAGS(flags, PTR_SYMBOL)) ptr_symbol++;
		if(CHECKFLAGS(flags, PTR_ENTRY)) ptr_entry++;
		if(CHECKFLAGS(flags, PTR_INVALID_INSTR)) ptr_invalid_instr++;
		if(CHECKFLAGS(flags, PTR_UNINT_INSTR)) ptr_unint_instr++;
		if(CHECKFLAGS(flags, PTR_UNINT_INSTR_NC)) ptr_unint_instr_nc++;
		if(CHECKFLAGS(flags, PTR_RETURN)) ptr_return++;
		if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_RETURN))) ptr_unint_return++;
		if(CHECKFLAGS(flags, PTR_UNKNOWN)) ptr_unknown++;
		if(CHECKFLAGS(flags, (PTR_UNINT_INSTR | PTR_GADGET))) ptr_unint_gadget++;
		if(CHECKFLAGS(flags, PTR_NOT_7f)) ptr_not_7f++;
		if(CHECKFLAGS(flags, (PTR_UNKNOWN)) &&
		   !CHECKFLAGS(flags, (PTR_NOT_7f))){
			ptr_unk_7f++;
		}
		if(CHECKFLAGS(flags, (PTR_UNKNOWN)) &&
		   !CHECKFLAGS(flags, (PTR_NOT_7f)) &&
		   CHECKFLAGS(flags, (PTR_END_PRINTABLE))){
			ptr_unk_7f_end_print++;
		}
	}

	//   << "Overall ptrs;"
	//   << "Unique ptrs;"
	//   << "Not PIE;"
	//   << "Ptr Known;"
	//   << "No corresponding section;"
	//   << "Ptr to plain file;"
	//   << "Ptr to start of section;"
	//   << "Pointer to Section != .text;"
	//   << "Ptr to String (.dynstr);"
	//   << "Ptr to Symbol (.dynsym)";
	//   << "Pointer to Symbol;"
	//   << "Pointer to EntryPoint;"
	//   << "Return Address;"
	//   << "Unknown Ptr;"
	//   << "Unknown Ptr Pie;"
	//   << "Unknown Pie End Printable"
	//   << "Invalid Instruction;"
	//   << "Unintended Instruction;"
	//   << "Unintended Instruction not checked;"
	//   << "Unintended Return instruction;"
	//   << "Unintended Usable Gadget;"

	std::stringstream ss;
	ss << ";" << overall
	   << ";" << ptr_class.size()
	   << ";" << ptr_not_7f
	   << ";" << ptr_class.size() - ptr_unknown
	   << ";" << ptr_no_section
//	   << ";" << ptr_plain_file
	   << ";" << ptr_section_start
	   << ";" << ptr_sec_not_text
	   << ";" << ptr_dynstr
	   << ";" << ptr_dynsym
	   << ";" << ptr_symbol
	   << ";" << ptr_entry
	   << ";" << ptr_return
	   << ";" << ptr_unknown
	   << ";" << ptr_unk_7f
	   << ";" << ptr_unk_7f_end_print
	   << ";" << ptr_invalid_instr
	   << ";" << ptr_unint_instr
	   << ";" << ptr_unint_instr_nc
	   << ";" << ptr_unint_return
	   << ";" << ptr_unint_gadget;

	return ss.str();
}

std::string printMappingInfo() {
	std::stringstream ss;
	ss << "Mapping summary"
	   << ";" << this->process->getPID()
	   << ";" << this->process->getName()
	   << ";" << this->fromVMA->name
	   << ";" << this->toVMA.name
	   << ";" << ((this->toLoader) ?0 :this->toLoader->elffile->getSymbolCount());
	return ss.str();
}

std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> showPtrs() {
	//std::cout << "Found " << count << " pointers:" << std::endl;
	uint64_t callAddr = 0;
	bool printKnown = false;
	std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> ptr_class;
	for (auto &ptr : ptrs) {
		ptr_class[ptr.first].first = ptr.second.size();

		uint64_t flags = 0;
		if (!(ptr.first >> 24)) SETFLAGS(flags, PTR_NOT_7f);

		auto toSec = this->toLoader->elffile->findSectionByOffset(ptr.first - toVMA.start);

		if(!toSec) {
			SETFLAGS(flags, PTR_NO_SECTION);
			if (printKnown) {
				std::cout << COLOR_MARGENTA << "Pointer to no section"
				          << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}

		if(!this->toLoader && !toVMA.name.empty()){
			SETFLAGS(flags, PTR_PLAIN_FILE);
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to Plain File:"
				          << "\t" << toVMA.name << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}

		if ((ptr.first - toVMA.start - toSec->offset) == 0) {
			SETFLAGS(flags, PTR_SECTION_START);
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to start of Section:"
				          << "\t" << toSec->name << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}


		if (toSec->name == ".dynstr"){
			SETFLAGS(flags, PTR_DYNSTR);
			if (printKnown) {
				std::string str = std::string((char*) toSec->index + (ptr.first - toVMA.start) - toSec->memindex);
				std::cout << COLOR_GREEN << "Pointer to String:"
				          << "\t" << str << std::endl << COLOR_NORM;
			}
		}

		if(toSec->name == ".dynsym"){
			SETFLAGS(flags, PTR_DYNSYM);
			if (printKnown) {
				std::string str = this->toLoader->elffile->dynSymbolName(ptr.first - toVMA.start - toSec->offset);
				std::cout << COLOR_GREEN << "Pointer to Symbol:"
				          << "\t" << str << std::endl << COLOR_NORM;
			}
		}

		std::unordered_set<std::string> allowedSections = {
			".data.rel.ro",
			".data.rel.ro.local",
			".dynamic",
			".dynstr",
			".dynsym",
			".eh_frame",
			".eh_frame_hdr",
			".gcc_except_table",
			".gnu.hash",
			".gnu.version",
			".gnu.version_d",
			".gnu.version_r",
			".got",
			".got.plt",
			".hash",
			".interp",
			".note.ABI-tag",
			".note.gnu.build-id",
			".plt",
			".plt.got",
			".rela.dyn",
			".rela.plt",
			".rodata",
			"__libc_IO_vtables",
			"__libc_thread_freeres_fn"
		};

		if(allowedSections.find(toSec->name) != allowedSections.end()) {
			SETFLAGS(flags, PTR_SEC_NOT_TEXT);
			if (printKnown) {
				std::cout << COLOR_MARGENTA << "Pointer to Section:"
				          << "\t" << toSec->name << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}

		auto symname = this->process->symbols.getElfSymbolName(ptr.first);
		if (symname != "") {
			SETFLAGS(flags, PTR_SYMBOL);
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to Symbol:"
				          << "\t" << symname << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}

		if (toLoader->elffile->entryPoint() == (ptr.first - toVMA.start)){
			SETFLAGS(flags, PTR_ENTRY);
			if (printKnown) {
				std::cout << COLOR_GREEN << "Pointer to Entry Point:"
				          << std::endl << COLOR_NORM;
			}
			ptr_class[ptr.first].second = flags;
			continue;
		}

		if (toSec->name == ".text") {
			assert(this->data);
		}

		uint64_t func = this->process->symbols.getContainingSymbol(ptr.first);
		std::string funcName = this->process->symbols.getElfSymbolName(func);

		if(!isValidInstruction(this->data,
		                       ptr.first - toVMA.start,
		                       toVMA.start)) {
			SETFLAGS(flags, PTR_UNKNOWN);
			SETFLAGS(flags, PTR_INVALID_INSTR);
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Pointer to invalid instruction! "
			          << COLOR_BOLD_OFF
			          << "Pointer to 0x" << std::setfill('0') << std::setw(8)
			          << std::hex << ptr.first - toVMA.start << " ( 0x"
			          << ptr.first << " ) " << std::dec << COLOR_RESET << std::endl;
			ptr_class[ptr.first].second = flags;
			continue;
		}

		//if(this->toLoader->elffile->getSymbolCount() &&
		if((ptr.first - func) > 0x4000) {
			SETFLAGS(flags, PTR_UNINT_INSTR_NC);
		} else if (!isIntendedInstruction(this->data + (func - toVMA.start),
		                                  ptr.first - func,
		                                  func)) {
			SETFLAGS(flags, PTR_UNKNOWN);
			SETFLAGS(flags, PTR_UNINT_INSTR);
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Pointer to 0x" << std::setfill('0') << std::setw(8)
			          << std::hex << ptr.first - toVMA.start << " ( 0x"
			          << ptr.first << " ) " << std::dec
			          << "\tPointer to unintended instruction!"
			          << COLOR_RESET << std::endl;
		}

		if((callAddr = isReturnAddress(this->data,
		                               ptr.first - toVMA.start,
		                               toVMA.start))) {
			SETFLAGS(flags, PTR_RETURN);

			if (printKnown | CHECKFLAGS(flags, (PTR_UNINT_INSTR))) {
				if (CHECKFLAGS(flags, PTR_UNINT_INSTR)) {
					std::cout << COLOR_RED << COLOR_BOLD
				          << "\tPointer to unintended return addres!"
					          << COLOR_RESET << std::endl;
				}
				uint64_t retFunc = this->process->symbols.getContainingSymbol(ptr.first);
				std::string retFuncName = this->process->symbols.getElfSymbolName(retFunc);

				std::cout << COLOR_GREEN << "Return Address to: "
				          << "\t" << retFuncName << std::endl << COLOR_NORM;
				if((callAddr) > 1) {
					std::string callFuncName = this->process->symbols.getElfSymbolName(callAddr);
					std::cout << COLOR_GREEN << "\tPreceeding call: "
					          << "\t" << callFuncName << std::endl << COLOR_NORM;
				}
			}

			if (!CHECKFLAGS(flags, (PTR_UNINT_INSTR))){
				ptr_class[ptr.first].second = flags;
				continue;
			}

		}

		SETFLAGS(flags, PTR_UNKNOWN);
		{
			// Check if pointer contains NULL byte followed by printable
			uint64_t ptr_cpy = ptr.first;
			unsigned char* ptr_char = (unsigned char*) &(ptr_cpy);
			bool foundNULL = false;
			bool endsPrintable = false;
			for(int i = 7; i >= 0 ; i--){
				if(!foundNULL and ptr_char[i] == '\0'){
					foundNULL = true;
					endsPrintable = true;
					continue;
				}
				if(foundNULL and (ptr_char[i] & 0x80)){
					foundNULL = false;
					endsPrintable = false;
				}
			}
			if(endsPrintable) {
				SETFLAGS(flags, PTR_END_PRINTABLE);
				std::cout << "Printable pointer: 0x" << std::hex << ptr.first << std::dec << std:: endl;
			}else{
				std::cout << "Not printable pointer: 0x" << std::hex << ptr.first << std::dec << std:: endl;
			}
		}

		std::cout << COLOR_RED
		          << "Pointer to 0x" << std::setfill('0') << std::setw(8)
		          << std::hex << ptr.first - toVMA.start << " ( 0x"
		          << ptr.first << " ) " << std::dec;
		if (toSec) {
			std::cout << "\tSection: " << toSec->name;
		}
		std::cout << std::endl;
		std::cout << "\tinto function: " << funcName << std::hex
		          << " (" << "offset: " << ptr.first - func << ")"
		          << std::dec << " From " << ptr.second.size() << " Locations"
		          << std::endl << COLOR_NORM;

		size_t offset = ptr.first - toVMA.start;
		uint64_t len = this->toLoader->getTextSegment().size() - offset;
		auto ret = printInstructions(this->data + offset, len, ptr.first);
		size_t nr_instr = std::get<0>(ret);
		bool end_valid = std::get<1>(ret);
		std::string instr = std::get<2>(ret);
		std::cout << COLOR_RED << COLOR_BOLD
		          << "\tPointing to gadget of " << nr_instr
		          << " instructions" << std::endl;
		if(end_valid) {
			std:: cout << "\tEnding in an invalid instruction!" << std::endl;
		}else{
			SETFLAGS(flags, PTR_GADGET);
		}
		std::cout << COLOR_RESET;
		ptr_class[ptr.first].second = flags;

	}
	return ptr_class;
}


protected:
	uint32_t count;
	std::map<uint64_t, std::set<uint64_t>> ptrs;
	Process *process;
	ElfLoader *fromLoader;
	ElfLoader *toLoader;
	const uint8_t *data;
	const VMAInfo *fromVMA;
	const VMAInfo toVMA;
};
// TODO: retrieve paths from command line parameters
ProcessValidator::ProcessValidator(ElfKernelLoader *kl,
                                   Process *process,
                                   VMIInstance *vmi)
    :
	vmi{vmi},
	kl{kl},
	process{process} {

	std::cout << "ProcessValidator got: " << this->process->getName() << std::endl;

	this->pid = process->getPID();
	std::cout << "[PID] " << this->pid << std::endl;
}

ProcessValidator::~ProcessValidator() {}

void printHeaders(){

	static bool done = false;
	if(done) return;
	done = true;

	std::stringstream ss1;
	std::stringstream ss2;

	ss1 << "Overall ptrs;"
	    << "Unique ptrs;"
	    << "Not PIE;"
	    << "Ptr Known;"
	    << "No corresponding section;"
//	    << "Ptr to plain file;"
	    << "Ptr to start of section;"
	    << "Pointer to Section != .text;"
	    << "Ptr to String (.dynstr);"
	    << "Ptr to Symbol (.dynsym);"
	    << "Pointer to Symbol;"
	    << "Pointer to EntryPoint;"
	    << "Return Address;"
	    << "Unknown Ptr;"
	    << "Unknown Ptr Pie;"
	    << "Unknown Pie End Printable;"
	    << "Invalid Instruction;"
	    << "Unintended Instruction;"
	    << "Unintended Instruction not checked;"
	    << "Unintended Return instruction;"
	    << "Unintended Usable Gadget";


	ss2 << "C1;C2;C3;C4;C5;C6;C7;C8;C9;C10;C11;C12;C13;C14;C15;C16;C17;C18;C19;C20";

	std::cout << "Process summary;PID;Name;" << ss1.str() << std::endl;
	std::cout << "Process summary;PID;Name;" << ss2.str() << std::endl;
	std::cout << "Section summary;PID;Name;SectionName;Symcount" << ss1.str() << std::endl;
	std::cout << "Section summary;PID;Name;SectionName;Symcount" << ss2.str() << std::endl;
	std::cout << "Mapping summary;PID;Name;FromMapping;ToMapping;Symcount" << ss1.str() << std::endl;
	std::cout << "Mapping summary;PID;Name;FromMapping;ToMapping;Symcount" << ss2.str() << std::endl;
}

int ProcessValidator::validateProcess() {
	static uint64_t execSize = 0;
	static uint64_t execPageCount = 0;
	static uint64_t dataSize = 0;
	static uint64_t dataPageCount = 0;

	// check if all mapped pages are known
	std::cout << COLOR_GREEN
	          << "Starting page validation ..."
	          << COLOR_RESET << std::endl;

	printHeaders();

	PageMap executablePageMap = this->vmi->getPages(this->pid);
	for (auto &page : executablePageMap) {
		// check if page is contained in VMAs
		if (!(page.second->vaddr & 0xffff800000000000) &&
		    !this->process->findVMAByAddress(page.second->vaddr)) {
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Found page that has no corresponding VMA: "
			          << std::hex << page.second->vaddr << std::dec
			          << COLOR_RESET << std::endl;
		}
	}
	this->vmi->destroyMap(executablePageMap);

	std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> glob_stats;
	// Check if all mapped VMAs are valid
	for (auto &section : this->process->getMappedVMAs()) {
		std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> stats;
		if(section.name == "[stack]" || section.name == "[heap]") {
			dataSize += section.end - section.start;
			dataPageCount++;
			stats = this->validateDataPage(&section);
		} else if (section.name[0] == '[') {
			continue;
		} else if ((section.flags & VMAInfo::VM_EXEC)) {
			execSize += section.end - section.start;
			execPageCount++;
			this->validateCodePage(&section);
		} else if ((section.flags & VMAInfo::VM_WRITE)) {
			dataSize += section.end - section.start;
			dataPageCount++;
			stats = this->validateDataPage(&section);
		}
		for (auto ptr : stats){
			auto tmp = glob_stats[ptr.first];
			if(tmp.first != 0 and tmp.second != ptr.second.second){
				assert(false);
			}
			glob_stats[ptr.first].first += ptr.second.first;
			glob_stats[ptr.first].second = ptr.second.second;
		}
	}

	if(glob_stats.size()) {
		std::cout << "Process summary"
		          << ";" << this->process->getPID()
		          << ";" << this->process->getName();
		std::cout << PagePtrInfo::printStat2(glob_stats);
		std::cout << std::endl;
	}

	// TODO count errors or change return value
	std::cout << "Validated " << execPageCount << " executable sections"
	          << " (" << (execSize / 0x1000) << " pages)"<< std::endl;
	std::cout << "Checked " << dataPageCount << " data sections"
	          << " (" << (dataSize / 0x1000) << " pages)"<< std::endl;
	return 0;
}

void ProcessValidator::validateCodePage(const VMAInfo *vma) const {
	std::vector<uint8_t> codevma;
	ElfUserspaceLoader *binary = nullptr;

	// check if the process name equals the vma name
	// -> use the exec loader and not some library loader
	if (this->process->getName().length() >= vma->name.length() &&
	    this->process->getName().compare(this->process->getName().length()
	                                     - vma->name.length(),
	                                     vma->name.length(),
	                                     vma->name) == 0) {
		binary = this->process->getExecLoader();
	} else {
		ElfUserspaceLoader *lib = this->process->findLoaderByFileName(vma->name);
		if (!lib) {
			// occurs when it's library is mapped but is not a dependency
			// TODO find out why libnss* is always mapped to the process space
			std::cout << COLOR_RED << "Warning: Found library in process "
			                          "that was not a dependency "
			          << vma->name << COLOR_RESET << std::endl;
			return;
		}
		binary = lib;
	}

	assert(binary);

	const uint8_t *fileContent = nullptr;
	const uint8_t *memContent  = nullptr;
	size_t textsize            = 0;
	size_t bytesChecked        = 0;

	fileContent = binary->textSegmentContent.data();
	textsize    = binary->textSegmentContent.size();

	while (bytesChecked < textsize) {
		// read vma from memory

		codevma = vmi->readVectorFromVA(vma->start + bytesChecked,
		                                vma->end - vma->start - bytesChecked,
		                                pid);
		memContent = codevma.data();

		for (size_t j = 0;
		     j < std::min(textsize - bytesChecked, codevma.size());
		     j++) {

			if (memContent[j] != fileContent[bytesChecked + j]) {
				std::cout << COLOR_RED << COLOR_BOLD
				          << "MISMATCH in code segment! " << vma->name
				          << COLOR_RESET
				          << std::endl;

				displayChange(memContent, fileContent + bytesChecked, j, textsize);
				return;
			}
		}
		bytesChecked += codevma.size();

		// An unmapped page can not be modified
		if (bytesChecked < textsize) {
			// std::cout << COLOR_RED << COLOR_BOLD <<
			//	"Some part of the text segment is not mapped in the VM" <<
			//	std::endl << "\t" << "Offset: " << vma->start + bytesChecked <<
			//	COLOR_RESET << std::endl;
			bytesChecked += PAGESIZE;
		}
	}
}



std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>>
ProcessValidator::validateDataPage(const VMAInfo *vma) const {
	// TODO: see if the start address of the mapping
	// is the address of GOT, then validate if symbols and
	// references are correct. elffile64 does the patching.

	std::unordered_map<uint64_t, std::pair<uint64_t, uint64_t>> glob_stats;

	std::vector<std::pair<VMAInfo, PagePtrInfo>> range;

	for (auto &toVMA : this->process->getMappedVMAs()) {
		if (CHECKFLAGS(toVMA.flags, VMAInfo::VM_EXEC)) {
			range.push_back(
				std::make_pair(
					toVMA,
					PagePtrInfo(process, vma, toVMA)
				)
			);
		}
	}

	auto content = vmi->readVectorFromVA(vma->start,
	                                     vma->end - vma->start,
	                                     this->pid, true);
	if (content.size() <= sizeof(uint64_t)) {
		// This page is currently not mapped
		return glob_stats;
	}

	uint8_t *data = content.data();

	for (uint64_t i = 0; i < content.size() - sizeof(uint64_t); i++) {
		// create pointer to current sec
		uint64_t *value = reinterpret_cast<uint64_t *>(data + i);

		// the pointer is never invalid as we're walking
		// over memory to verify.
		if (*value == 0) {
			continue;
		}

		for (auto &mapping : range) {
			if (CHECKFLAGS(mapping.first.flags, VMAInfo::VM_EXEC)) {
				if (vma->name == mapping.first.name) {
					// points to the same mapping
					break;
				}

				if (IN_RANGE(*value, mapping.first.start + 1, mapping.first.end)) {
					if (*value == mapping.first.start + 0x40) {
						// Pointer to PHDR
						break;
					}
					mapping.second.addPtr(i, *value);
				}
			}
		}
	}

	// resolve-trampoline:
	// sysdeps/x86_64/dl-trampoline.S:64
	// LD_BIND_NOW forces load-time relocations.


	for (auto &mapping : range) {
		auto && stats = mapping.second.showPtrs();

		if(stats.size() == 0) continue;

		std::cout << mapping.second.printMappingInfo();
		std::cout << PagePtrInfo::printStat(stats);
		std::cout << std::endl;

		size_t unknown = 0;
		for (auto ptr : stats){
			if (CHECKFLAGS(ptr.second.second, PagePtrInfo::PTR_UNKNOWN)) unknown++;
			auto tmp = glob_stats[ptr.first];
			if(tmp.first != 0 and tmp.second != ptr.second.second){
				assert(false);
			}
			glob_stats[ptr.first].first += ptr.second.first;
			glob_stats[ptr.first].second = ptr.second.second;
		}

		if(unknown) {
			std::cout << "Pointers from " << ((vma->name[0] == '[') ? process->getName() + " " + vma->name :vma->name)
			          << " to " << mapping.first.name << std::endl;
		}

		// TODO mapping.second.printSummary();
	}
	size_t unknown = 0;
	for (auto ptr : glob_stats){
		if (CHECKFLAGS(ptr.second.second, PagePtrInfo::PTR_UNKNOWN)) unknown++;
	}

	if(unknown) {
		std::cout << "Found " << COLOR_RED << COLOR_BOLD
		      << std::setfill(' ') << std::setw(5)
		      << unknown << COLOR_RESET << " unknown ("
		      << COLOR_GREEN << std::setw(5) << glob_stats.size() << COLOR_RESET << ")"
		      << " pointers: ";
		vma->print();
	}
	
	if(glob_stats.size()){
		ElfUserspaceLoader * fromLoader;
		if (vma->name[0] != '[') {
			fromLoader = this->process->findLoaderByFileName(vma->name);
		} else {
			fromLoader = this->process->getExecLoader();
		}

		std::cout << "Segment summary"
		          << ";" << this->process->getPID()
		          << ";" << this->process->getName()
		          << ";" << vma->name
		          << ";" << ((fromLoader)? fromLoader->elffile->getSymbolCount() :0);
		std::cout << PagePtrInfo::printStat(glob_stats);
		std::cout << std::endl;
	}

	return glob_stats;

}


std::vector<uint8_t> ProcessValidator::getStackContent(
    size_t readAmount) const {
	const VMAInfo *stack = process->findVMAByName("[stack]");

	return vmi->readVectorFromVA(stack->end - readAmount, readAmount, this->pid, true);
}

int ProcessValidator::checkEnvironment(const std::map<std::string, std::string> &inputMap) {
	int errors  = 0;
	auto envMap = this->kl->getTaskManager()->getEnvForTask(this->pid);

	// check all input settings
	for (auto &inputPair : inputMap) {
		if (envMap.find(inputPair.first) != envMap.end()) {
			if (envMap[inputPair.first].compare(inputPair.second) == 0) {
				// setting is right
				continue;
			} else {
				// setting is wrong
				errors++;
				std::cout << COLOR_RED
				          << "Found mismatch in environment variables on entry "
				          << inputPair.first << ". Expected: '"
				          << inputPair.second << "', found: '"
				          << envMap[inputPair.first] << "'." << COLOR_NORM
				          << std::endl;
			}
		}
	}
	return errors;
}

} // namespace kernint
