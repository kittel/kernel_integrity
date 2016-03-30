#ifndef KERNINT_HELPERS_H_
#define KERNINT_HELPERS_H_

#define UNUSED(expr) do { (void)(expr); } while (0)
#define DELETE(expr) do { if(expr){ delete expr; expr = 0; }; } while (0)

#define CHECKFLAGS(byte, flags)    !!((byte & flags) == flags)
#define CONTAINS(min, size, what)  (what >= min && what <= min + size)
#define IN_RANGE(value, left, right) (value >= left && value <= right)

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

/** print memory mismatches */
void displayChange(const uint8_t *memory,
                   const uint8_t *reference,
                   int32_t offset,
                   int32_t size);

/* Convert a C-String into a std::string for gdb use (don't use elsewhere) */
[[deprecated("don't use this gdb helper")]]
inline std::string& toSTDstring(const char *input) {
	return *(new std::string(input));
}

/* Reduce given path to filename */
inline std::string getNameFromPath(const std::string &path) {
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
                                   std::vector<uint8_t> *target){
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

/**
 * Perform a static cast for unique pointers.
 */
template <typename Target, typename Current, typename Del>
std::unique_ptr<Target, Del> static_cast_unique_ptr(std::unique_ptr<Current, Del> &&p) {
	auto d = static_cast<Target *>(p.release());
	return std::unique_ptr<Target, Del>(d, std::move(p.get_deleter()));
}

/**
 * Performs a dynamic cast for unique ptrs.
 * When the cast is invalid, return a nullptr.
 */
template <typename Target, typename Current, typename Del>
std::unique_ptr<Target, Del> dynamic_cast_unique_ptr(std::unique_ptr<Current, Del> &&p) {
	if (Target *result = dynamic_cast<Target *>(p.get())) {
		p.release();
		auto deleter = p.get_deleter();
		return std::unique_ptr<Target, Del>(result, std::move(deleter));
	}
	return std::unique_ptr<Target, Del>(nullptr, p.get_deleter());
}

inline
size_t offset(const char* buf, size_t len, const char* str) {
	return std::search(buf, buf + len, str, str + strlen(str)) - buf;
}

#endif
