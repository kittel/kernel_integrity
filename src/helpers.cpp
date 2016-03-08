#include "helpers.h"

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
