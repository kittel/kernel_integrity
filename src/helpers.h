#ifndef _HELPERS_H_
#define _HELPERS_H_

#define UNUSED(expr) do { (void)(expr); } while (0)
#define DELETE(expr) do { if(expr){ delete expr; expr = 0; }; } while (0)

#define CHECKFLAGS(byte, flags)    !!((byte & flags) == flags)
#define CONTAINS(min, size, what)  (min <= what && min + size >= what)

#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <fstream>
#include <iostream>

#define	COLOR_RESET         "\033[0m"
#define	COLOR_NORM          "\033[39m"
#define	COLOR_GRAY          "\033[30m"
#define	COLOR_RED           "\033[31m"
#define	COLOR_GREEN         "\033[32m"
#define	COLOR_YELLOW        "\033[33m"
#define	COLOR_BLUE          "\033[34m"
#define	COLOR_MARGENTA      "\033[35m"
#define	COLOR_CYAN          "\033[36m"
#define	COLOR_WHITE         "\033[37m"
#define	COLOR_CRIMSON       "\033[38m"

#define	COLOR_BOLD          "\033[1m"
#define	COLOR_BOLD_OFF      "\033[22m"
#define	COLOR_FAINT         "\033[2m"
#define	COLOR_FAINT_OFF     "\033[22m"
#define	COLOR_ITALIC        "\033[3m"
#define	COLOR_ITALIC_OFF    "\033[23m"
#define	COLOR_UNDERLINE     "\033[4m"
#define	COLOR_UNDERLINE_OFF "\033[24m"

// determining updateMemIndex target. extendable.
#define SEG_NR_TEXT 0
#define SEG_NR_DATA 1

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

inline std::string toString(uint8_t * string){
	return std::string((const char*) string);
}

inline void printHexDump(const std::vector<uint8_t> *bytes){
	using namespace std;

	unsigned long address = 0;
	int nread = 0; //buffer filler [0,16]
	char buf[16];

	cout << hex << setfill('0');
	auto lenBytes = bytes->size();

	while(address < lenBytes){

		//get 16 bytes into the fresh buffer
		for( nread = 0; nread < 16; nread++){buf[nread] = 0;}; // clear buf
		for( nread = 0; nread < 16 && (address + nread < lenBytes); nread++ ){
			buf[nread] = (*bytes)[(address + nread)];
		}

		if( address + nread > lenBytes ) break;

		// Show the address
		cout << right << setw(8) << address << ":";

		// Show the hex codes
		for( int i = 0; i < 16; i++ )
		{
			/* Format in pairs of two
			if( i % 8 == 0 ) cout << ' ';
			if( i < nread ){
				cout << ' ' << setw(2) << ((unsigned)buf[i] & 0x000000ff);
			}
			else{ 
				cout << "	";
			}
			*/

			/* Format in pairs of 4 (xxd-style) */
			if(i % 2 == 0) cout << ' ';
			if(i < nread ){
				cout << setw(2) << ((unsigned)buf[i] & 0x000000ff);
			}
			else{
				cout << ">>";
			}
		}

		// Show printable characters
		cout << "  ";
		for( int i = 0; i < nread; i++)
		{
			if( buf[i] < 32 || buf[i] > 126 ) cout << '.';
			else cout << buf[i];
		}

		cout << "\n";
		address += 16;
	}
	return;
}

/* Convert a C-String into a std::string for gdb use (don't use elsewhere)*/
inline std::string& toSTDstring(const char *input){
	return *(new std::string(input));
}

/* Reduce given path to filename */
inline std::string getNameFromPath(const std::string path){
	std::string ret = path.substr(path.rfind("/", std::string::npos) + 1,
									std::string::npos);
	return ret;
}

inline void dumpToFile(std::string filename, std::vector<uint8_t> content){
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

inline bool fexists(const std::string filename)
{
	std::ifstream ifile(filename);
	return ifile.good();
}

#define contained(value, left, right) (value >= left && value <= right)

template<typename T>
inline bool betweenRange(T value, std::vector<std::pair<T, T>> r){
	for( auto& elem : r ){
		if(contained(value, elem.first, elem.second)) return true;
	}
	return false;
}
#endif /* _HELPERS_H_ */
