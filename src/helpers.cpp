#include "helpers.h"

#include <cxxabi.h>
#include <dlfcn.h>

#include <capstone/capstone.h>


namespace kernint {

void printHexDump(const std::vector<uint8_t> *bytes) {
	using namespace std;

	unsigned long address = 0;
	int nread             = 0;  // buffer filler [0,16]
	char buf[16];

	cout << hex << setfill('0');
	auto lenBytes = bytes->size();

	while (address < lenBytes) {
		// get 16 bytes into the fresh buffer
		for (nread = 0; nread < 16; nread++) {
			buf[nread] = 0;  // clear buf
		}
		for (nread = 0; nread < 16 && (address + nread < lenBytes); nread++) {
			buf[nread] = (*bytes)[(address + nread)];
		}

		if (address + nread > lenBytes) {
			break;
		}

		// Show the address
		cout << right << setw(8) << address << ":";

		// Show the hex codes
		for (int i = 0; i < 16; i++) {
			/* Format in pairs of 4 (xxd-style) */
			if (i % 2 == 0) {
				cout << ' ';
			}
			if (i < nread) {
				cout << setw(2) << ((unsigned)buf[i] & 0x000000ff);
			} else {
				cout << ">>";
			}
		}

		// Show printable characters
		cout << "  ";
		for (int i = 0; i < nread; i++) {
			if (buf[i] < 32 || buf[i] > 126) {
				cout << '.';
			} else {
				cout << buf[i];
			}
		}

		cout << endl;
		address += 16;
	}

	cout << hex;
	return;
}

void displayChange(const uint8_t *memory,
                   const uint8_t *reference,
                   int32_t offset,
                   int32_t size) {
	std::cout << "First change"
	          << " in byte 0x" << std::hex << offset << " is 0x"
	          << (uint32_t)reference[offset] << " should be 0x"
	          << (uint32_t)memory[offset] << std::dec << std::endl;

	// Print 40 Bytes from should be

	std::cout << "The loaded block is: " << std::hex << std::endl;
	for (int32_t k = offset - 15; (k < offset + 15) && (k < size); k++) {
		if (k < 0 || k >= size)
			continue;
		if (k == offset)
			std::cout << " # ";
		std::cout << std::setfill('0') << std::setw(2) << (uint32_t)reference[k]
		          << " ";
	}

	std::cout << std::endl << "The block in mem is: " << std::hex << std::endl;
	for (int32_t k = offset - 15; (k < offset + 15) && (k < size); k++) {
		if (k < 0 || k >= size)
			continue;
		if (k == offset)
			std::cout << " # ";
		std::cout << std::setfill('0') << std::setw(2) << (uint32_t)memory[k]
		          << " ";
	}

	std::cout << std::dec << std::endl << std::endl;
}


std::string findFileInDir(std::string dirName,
                          std::string fileName,
                          std::string extension,
                          std::vector<std::string> exclude) {

	boost::system::error_code ec;
	std::regex regex = std::regex(fileName);
	for (fs::recursive_directory_iterator end, dir(dirName, ec);
	     dir != end;
	     dir.increment(ec)) {

		assert(ec.value() == 0);

		if (dir.level() == 0) {
			for (auto &string : exclude) {
				if (dir->path().filename() == string) {
					dir.no_push();
					continue;
				}
			}
		}

		if (!is_directory(*dir) &&
		    extension.compare(dir->path().extension().string()) == 0) {
			if (std::regex_match(std::string(dir->path().stem().string()),
			                     regex)) {
				return std::string(dir->path().native());
			}
		}
	}
	return "";
}

class Capstone {
public:
	static csh getHandle(){
		if(!instance) {
			instance = new Capstone();
		}
		return instance->handle;
	}

private:
	static Capstone *instance;

	csh handle;

	Capstone(){
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			assert(false);
	}
	~Capstone(){
		cs_close(&handle);
	}

};

Capstone* Capstone::instance = nullptr;

std::tuple<size_t, bool, std::string>
printInstructions(const uint8_t *ptr, uint32_t offset, uint64_t index){
	csh handle = Capstone::getHandle();
	cs_insn *insn = cs_malloc(handle);
	size_t nr_inst = 0;
	std::stringstream ss;

	// Check if current instruction may be disassembled
	const uint8_t* code = ptr;
	uint64_t cs_ptr = index;
	size_t size = offset;
	while(cs_disasm_iter(handle, &code, &size, &cs_ptr, insn)){
		nr_inst++;
		ss << insn->mnemonic << "\t" << insn->op_str << std::endl;
		if(strcmp(insn->mnemonic, "ret") == 0) break;
	}
	cs_free(insn, 1);
	return std::make_tuple(nr_inst, (size == 0), ss.str());
}

bool isIntendedInstruction(const uint8_t *ptr, uint32_t offset, uint64_t index) {
	csh handle = Capstone::getHandle();
	cs_insn *insn = cs_malloc(handle);

	// Check if current instruction may be disassembled
	const uint8_t* code = ptr + offset;
	uint64_t cs_ptr = index + offset;
	size_t size = offset + 10;
	while(cs_disasm_iter(handle, &code, &size, &cs_ptr, insn) and code < ptr + offset);
	cs_free(insn, 1);
	return (code == ptr + offset);
}

bool isValidInstruction(const uint8_t *ptr, uint32_t offset, uint64_t index) {
	bool ret = false;
	csh handle = Capstone::getHandle();
	cs_insn *insn = cs_malloc(handle);

	// Check if current instruction may be disassembled
	const uint8_t* code = ptr + offset;
	uint64_t cs_ptr = index + offset;
	size_t size = 10;
	if (cs_disasm_iter(handle, &code, &size, &cs_ptr, insn)) {
		ret = true;
	}
	cs_free(insn, 1);
	return ret;
}


uint64_t isReturnAddress(const uint8_t *ptr, uint32_t offset, uint64_t index,
                         VMIInstance * /*vmi*/, uint32_t /*pid*/) {
	// List of return values:
	//
	// NOT_AN_INSTRUCTON
	// NOT_AFTER_CALL

	uint64_t address = 0;

	csh handle = Capstone::getHandle();
	cs_insn *insn = cs_malloc(handle);

	if(!isValidInstruction(ptr, offset, index))
		return 0;

	// TODO maybe a relative jump is expected
	int i = 0;
	for(i = 2; i < 8; i++){
		//Check if previous instruction is a call
		const uint8_t *code = ptr + offset - i;
		uint64_t cs_ptr = index + offset - i;
		size_t size = 20;

		if (cs_disasm_iter(handle, &code, &size, &cs_ptr, insn) and
		    insn->size == i and
		    (strcmp(insn->mnemonic, "call")  == 0 ||
		     strcmp(insn->mnemonic, "lcall") == 0)) {
			if (insn->op_str[0] == '0' and insn->op_str[1] == 'x'){
				address = (uint64_t)strtol(insn->op_str + 2, NULL, 16);;
			} else {
				address = 1;
			}
			break;
		}
	}
	cs_free(insn, 1);
	return address;

	// // TODO:  warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'int32_t *' (aka 'int *') increases required alignment from 1 to 4
	// int32_t *callOffset = (int32_t*) (ptr + offset - 4);
	// if (offset > 2 && ptr[offset - 2] == (uint8_t)0xff) {
	// 	return 1;
	// }
	// if (offset > 3 && ptr[offset - 3] == (uint8_t)0xff) {
	// 	// call qword [rbx+0x0]
	// 	return 1;
	// }
	// if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe8) {
	// 	// call qword 0x5
	// 	return index + offset + *callOffset;
	// }
	// if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe9) {
	// 	// jmp qword
	// 	// This is a jmp instruction!
	// 	return 0;
	// }
	// if (offset > 5 && ptr[offset - 5] == (uint8_t)0x41 &&
	// 	ptr[offset - 4] == (uint8_t)0xff) {
	// 	// callq *0x??(%r??)
	// 	return 1;
	// }
	// if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	//     ptr[offset - 5] == (uint8_t)0x90) {
	// 	// call qword [rax+0x0]
	// 	// return 1 as we do not know rax
	// 	return 1;
	// }
	// if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	//     ptr[offset - 5] == (uint8_t)0x95) {
	// 	// ff 95 88 00 00 00       callq  *0x88(%rbp)
	// 	return 1;
	// }
	// if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	//     ptr[offset - 5] == (uint8_t)0x15) {
	// 	// call qword [rel 0x6]
	// 	uint64_t callAddr = index + offset + *callOffset;
	// 	return vmi->read64FromVA(callAddr, pid);
	// }
	// if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	//     ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0x25) {
	// 	// call qword [0x0]
	// 	// std::cout << "INVESTIGATE!" << std::endl;
	// 	return 1;
	// }
	// if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	//     ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0xc5) {
	// 	// call   QWORD PTR [rax*8-0x0]
	// 	return 1;
	// }

	// return 0;
}

namespace util {

bool hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}

std::string demangle(const char *symbol) {
	int status;
	char *buf = abi::__cxa_demangle(symbol, nullptr, nullptr, &status);

	if (status != 0) {
		return symbol;
	} else {
		std::string result{buf};
		free(buf);
		return result;
	}
}


std::string addr_to_string(const void *addr) {
	std::ostringstream out;
	out << "[" << addr << "]";
	return out.str();
}


std::string symbol_name(const void *addr,
                        bool require_exact_addr, bool no_pure_addrs) {
	Dl_info addr_info;

	if (dladdr(addr, &addr_info) == 0) {
		// dladdr has... failed.
		return no_pure_addrs ? "" : addr_to_string(addr);
	} else {
		size_t symbol_offset = reinterpret_cast<size_t>(addr) -
		                       reinterpret_cast<size_t>(addr_info.dli_saddr);

		if (addr_info.dli_sname == nullptr or
		    (symbol_offset != 0 and require_exact_addr)) {

			return no_pure_addrs ? "" : addr_to_string(addr);
		}

		if (symbol_offset == 0) {
			// this is our symbol name.
			return demangle(addr_info.dli_sname);
		} else {
			std::ostringstream out;
			out << demangle(addr_info.dli_sname)
			    << "+0x" << std::hex
			    << symbol_offset << std::dec;
			return out.str();
		}
	}
}

} // namespace util
} // namespace kernint
