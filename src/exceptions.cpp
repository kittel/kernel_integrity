#include "exceptions.h"

ElfException::ElfException() throw() {}

ElfException::ElfException(const char* reason) throw()
	:
	reason(reason) {}

ElfException::~ElfException() throw() {}

const char* ElfException::what() const throw() {
	std::string result = std::string("ElfException: ");
	return result.append(this->reason).c_str();
}

VMIException::VMIException() throw() {}

VMIException::VMIException(const char* reason) throw()
	:
	reason(reason) {}

VMIException::~VMIException() throw() {}

const char* VMIException::what() const throw() {
	std::string result = std::string("VMIException: ");
	return result.append(this->reason).c_str();
}

NotImplementedException::NotImplementedException() throw() {}
NotImplementedException::NotImplementedException(const char* reason) throw()
	:
	reason(reason) {}

NotImplementedException::~NotImplementedException() throw() {}

const char* NotImplementedException::what() const throw() {
	std::string result = std::string("NotImplementedException: ");
	return result.append(this->reason).c_str();
}
