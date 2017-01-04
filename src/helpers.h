#ifndef KERNINT_HELPERS_H_
#define KERNINT_HELPERS_H_

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;

#include "libvmiwrapper/vmiinstance.h"

#define COLOR_RESET         "\033[0m"
#define COLOR_NORM          "\033[39m"
#define COLOR_GRAY          "\033[30m"
#define COLOR_RED           "\033[31m"
#define COLOR_GREEN         "\033[32m"
#define COLOR_YELLOW        "\033[33m"
#define COLOR_BLUE          "\033[34m"
#define COLOR_MARGENTA      "\033[35m"
#define COLOR_CYAN          "\033[36m"
#define COLOR_WHITE         "\033[37m"
#define COLOR_CRIMSON       "\033[38m"
#define COLOR_BOLD          "\033[1m"
#define COLOR_BOLD_OFF      "\033[22m"
#define COLOR_FAINT         "\033[2m"
#define COLOR_FAINT_OFF     "\033[22m"
#define COLOR_ITALIC        "\033[3m"
#define COLOR_ITALIC_OFF    "\033[23m"
#define COLOR_UNDERLINE     "\033[4m"
#define COLOR_UNDERLINE_OFF "\033[24m"


#define UNUSED(expr) do { (void)(expr); } while (0)
#define DELETE(expr) do { if(expr){ delete expr; expr = 0; }; } while (0)

#define CHECKFLAGS(byte, flags)    !!((byte & flags) == flags)
#define CONTAINS(min, size, what)  (what >= min && what < min + size)
#define IN_RANGE(value, left, right) (value >= left && value <= right)


/*
 * Branch prediction tuning.
 * The expression is expected to be true (=likely) or false (=unlikely).
 */
#define likely(x)    __builtin_expect(!!(x), 1)
#define unlikely(x)  __builtin_expect(!!(x), 0)


namespace kernint {

inline std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
	std::stringstream ss(s);
	std::string item;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}


inline std::vector<std::string> split(const std::string &s, char delim) {
	std::vector<std::string> elems;
	split(s, delim, elems);
	return elems;
}

inline std::string toString(const uint8_t *string) {
	return std::string(reinterpret_cast<const char *>(string));
}

/** print a hexdump of some memory */
void printHexDump(const std::vector<uint8_t> *bytes);

constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

inline std::string hexStr(unsigned char *data, int len){
	std::string s(len * 2, ' ');
	for (int i = 0; i < len; ++i) {
		s[2 * i]     = hexmap[(data[i] & 0xF0) >> 4];
		s[2 * i + 1] = hexmap[data[i] & 0x0F];
	}
	return s;
}

/** print memory mismatches */
void displayChange(const uint8_t *memory,
                   const uint8_t *reference,
                   int32_t offset,
                   int32_t size);

inline
uint64_t isReturnAddress(const uint8_t *ptr, uint32_t offset, uint64_t index,
                         VMIInstance *vmi=nullptr, uint32_t pid=0) {

	// TODO:  warning: cast from 'uint8_t *' (aka 'unsigned char *') to 'int32_t *' (aka 'int *') increases required alignment from 1 to 4
	int32_t *callOffset = (int32_t*) (ptr + offset - 4);
	if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe8) {
		// call qword 0x5
		return index + offset + *callOffset;
	}
	if (offset > 5 && ptr[offset - 5] == (uint8_t)0xe9) {
		// jmp qword
		// This is a jmp instruction!
		return 0;
	}
	if (offset > 5 && ptr[offset - 5] == (uint8_t)0x41 &&
		ptr[offset - 4] == (uint8_t)0xff) {
		// callq *0x??(%r??)
		return 1;
	}
	if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	    ptr[offset - 5] == (uint8_t)0x90) {
		// call qword [rax+0x0]
		// return 1 as we do not know rax
		return 1;
	}
	if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	    ptr[offset - 5] == (uint8_t)0x95) {
		// ff 95 88 00 00 00       callq  *0x88(%rbp)
		return 1;
	}
	if (offset > 6 && ptr[offset - 6] == (uint8_t)0xff &&
	    ptr[offset - 5] == (uint8_t)0x15) {
		// call qword [rel 0x6]
		uint64_t callAddr = index + offset + *callOffset;
		return vmi->read64FromVA(callAddr, pid);
	}
	if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	    ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0x25) {
		// call qword [0x0]
		// std::cout << "INVESTIGATE!" << std::endl;
		return 1;
	}
	if (offset > 7 && ptr[offset - 7] == (uint8_t)0xff &&
	    ptr[offset - 6] == (uint8_t)0x14 && ptr[offset - 5] == (uint8_t)0xc5) {
		// call   QWORD PTR [rax*8-0x0]
		return 1;
	}
	if (offset > 2 && ptr[offset - 2] == (uint8_t)0xff) {
		return 1;
	}
	if (offset > 3 && ptr[offset - 3] == (uint8_t)0xff) {
		// call qword [rbx+0x0]
		return 1;
	}

	return 0;
}


/* Convert a C-String into a std::string for gdb use (don't use elsewhere) */
[[deprecated("don't use this gdb helper")]]
inline std::string& toSTDstring(const char *input) {
	return *(new std::string(input));
}

/* Reduce given path to filename */
inline std::string getNameFromPath(const std::string &path) {
	// TODO: use filesystem::path::canonical()::filename()
	std::string ret = path.substr(path.rfind("/", std::string::npos) + 1,
	                              std::string::npos);
	return ret;
}

inline
void dumpToFile(const std::string &filename,
                const std::vector<uint8_t> &content){
	std::ofstream outfile (filename, std::ofstream::binary);
	outfile.write((char*) content.data(), content.size());
	outfile.close();
}

inline uint32_t appendDataToVector(const void *data, uint32_t len,
                                   std::vector<uint8_t> *target) {
	uint8_t *input = (uint8_t*) data;
	target->insert(target->end(), input, (input + len));
	return len;
}

inline bool fexists(const std::string &filename) {
	std::ifstream ifile(filename);
	return ifile.good();
}

std::string findFileInDir(std::string dirName,
                          std::string fileName,
                          std::string extension,
                          std::vector<std::string> exclude=std::vector<std::string>());


template<typename T>
inline bool betweenRange(T value, const std::vector<std::pair<T, T>> &r){
	for (auto &elem : r) {
		if (value >= elem.first && value <= elem.second) {
			return true;
		}
	}
	return false;
}


inline
size_t offset(const char* buf, size_t len, const char* str) {
	return std::search(buf, buf + len, str, str + strlen(str)) - buf;
}


namespace util {

/**
 * Check if a given string ends with another string.
 */
bool hasEnding (std::string const &fullString, std::string const &ending);

/**
 * Demangles a symbol name.
 *
 * On failure, the mangled symbol name is returned.
 */
std::string demangle(const char *symbol);

/**
 * Return the demangled symbol name for a given code address.
 */
std::string symbol_name(const void *addr, bool require_exact_addr=true, bool no_pure_addrs=false);

} // namespace util
} // namespace kernint

#endif
