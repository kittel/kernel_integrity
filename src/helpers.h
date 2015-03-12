#ifndef _HELPERS_H_
#define _HELPERS_H_

#define UNUSED(expr) do { (void)(expr); } while (0)
#define DELETE(expr) do { if(expr){ delete expr; expr = 0; }; } while (0)

#include <string>
#include <sstream>
#include <vector>

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

#endif /* _HELPERS_H_ */
