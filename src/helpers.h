#ifndef _HELPERS_H_
#define _HELPERS_H_

#define UNUSED(expr) do { (void)(expr); } while (0)
#define DELETE(expr) do { if(expr){ delete expr; expr = 0; }; } while (0)

#define CHECKFLAGS(byte, flags)    !!((byte & flags) == flags)
#define CONTAINS(min, size, what)  (min <= what && min + size >= what)
#define contained(value, left, right) (value >= left && value <= right)

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

inline std::string toString(uint8_t * string) {
	return std::string((const char*) string);
}

inline void printHexDump(const std::vector<uint8_t> *bytes){
	using namespace std;

	unsigned long address = 0;
	int nread = 0; //buffer filler [0,16]
	char buf[16];

	cout << hex << setfill('0');
	auto lenBytes = bytes->size();

	while (address < lenBytes) {

		//get 16 bytes into the fresh buffer
		for (nread = 0; nread < 16; nread++) {
			buf[nread] = 0; // clear buf
		}
		for (nread = 0; nread < 16 && (address + nread < lenBytes); nread++ ){
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
			if (i < nread ) {
				cout << setw(2) << ((unsigned)buf[i] & 0x000000ff);
			}
			else{
				cout << ">>";
			}
		}

		// Show printable characters
		cout << "  ";
		for (int i = 0; i < nread; i++) {
			if (buf[i] < 32 || buf[i] > 126 ) {
				cout << '.';
			}
			else {
				cout << buf[i];
			}
		}

		cout << "\n";
		address += 16;
	}
	return;
}

inline void displayChange(const uint8_t *memory,
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

/* Convert a C-String into a std::string for gdb use (don't use elsewhere) */
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

inline std::string findFileInDir(std::string dirName,
            std::string fileName,
            std::string extension,
            std::vector<std::string> exclude = std::vector<std::string>()) {
	//static std::mutex mutex;
	//std::lock_guard<std::mutex> lock(mutex);
	boost::system::error_code ec;
	std::regex regex = std::regex(fileName);
	for (fs::recursive_directory_iterator end, dir(dirName, ec);
	       dir != end; dir.increment(ec)) {
		assert(ec.value() == 0);
		if(dir.level() == 0) {
			for ( auto& string : exclude ) {
				if (dir->path().filename() == string) {
					dir.no_push();
					continue;
				}
			}
		}
		if (!is_directory(*dir) &&
		    extension.compare(dir->path().extension().string()) == 0) {
			if (std::regex_match(std::string(dir->path().stem().string()), regex)) {
				return std::string(dir->path().native());
			}
		}
	}
	return "";
}

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
size_t offset(const char* buf, size_t len, const char* str)
{
	return std::search(buf, buf + len, str, str + strlen(str)) - buf;
}

#endif /* _HELPERS_H_ */
