#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <exception>
#include <string>

class ElfException : std::exception {
public:
	ElfException() throw();
	ElfException(const char* reason) throw();
	virtual ~ElfException() throw();
	const char* what() const throw() override;

private:
	std::string reason;
};

class NotImplementedException : std::exception {
public:
	NotImplementedException() throw();
	NotImplementedException(const char* reason) throw();
	virtual ~NotImplementedException() throw();
	const char* what() const throw() override;

private:
	std::string reason;
};

class VMIException : std::exception {
public:
	VMIException() throw();
	VMIException(const char* reason) throw();
	virtual ~VMIException() throw();
	const char* what() const throw() override;

private:
	std::string reason;
};

#endif /* EXCEPTION_H */
