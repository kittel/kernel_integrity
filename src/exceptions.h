#ifndef KERNINT_EXCEPTION_H_
#define KERNINT_EXCEPTION_H_

#include <exception>
#include <string>


namespace kernint {

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

} // namespace kernint

#endif
