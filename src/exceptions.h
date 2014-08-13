#ifndef EXCEPTION_H
#define EXCEPTION_H

#include <exception>
#include <string>

class ElfException : std::exception {
	public:
		ElfException() throw();
		ElfException(const char* reason) throw();
		virtual ~ElfException() throw();
		virtual const char* what() const throw();

	private:
		std::string reason;
};


class NotImplementedException : std::exception {
	public:
		NotImplementedException() throw();
		NotImplementedException(const char* reason) throw();
		virtual ~NotImplementedException() throw();
		virtual const char* what() const throw();

	private:
		std::string reason;
};

class VMIException : std::exception {
	public:
		VMIException() throw();
		VMIException(const char* reason) throw();
		virtual ~VMIException() throw();
		virtual const char* what() const throw();

	private:
		std::string reason;
};



#endif  /* EXCEPTION_H */
