#include <cassert>
#include <typeinfo>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <csignal>
#include <chrono>
#include <getopt.h>

#include <kernelvalidator.h>
#include <processvalidator.h>

void signalHandler( int signum ){
	UNUSED(signum);
	KernelValidator* instance = 
		KernelValidator::getInstance();
	if(instance){
		instance->setOptions(false, false, false);
	}
}


void validateKernel(KernelValidator* val){
	const auto time_start = std::chrono::system_clock::now();
	
	uint64_t iterations = val->validatePages();

	const auto time_stop = std::chrono::system_clock::now();

	const auto d_actual = 
		std::chrono::duration_cast<std::chrono::milliseconds>
		                          (time_stop - time_start).count();

	std::cout << "Executed " << iterations << " iterations in " <<
		d_actual << " ms ( " << 
		(((double) d_actual) / iterations) << " ms/iteration) " << std::endl;
}

void validateUserspace(ProcessValidator* val, VMIInstance* vmi, uint32_t pid){
#ifdef DEBUG
	std::cout << "ProcessValidator created." << std::endl;
	std::cout << "debug: Trying to get (Executable) Pages of Process <" 
              << std::dec << pid << "> ..." << std::endl;
#endif
	std::cout << "Loading pages to verify from VM..." << std::endl;
	//PageMap executablePageMap = vmi->getExecutableUserspacePages(pid);
	PageMap executablePageMap = vmi->getUserspacePages(pid);

	uint32_t errors = 0;

	// check process environment
	std::cout << "Loading environment variables from process " << std::dec << pid
	<< " ..." << std::endl;
	val->getProcessEnvironment(vmi, pid); // (vmi, pid, offset) possible for aslr offset
	std::cout << "Checking environment variable values..." << std::endl;

	// whitelisted values for environment
	// if LD_BIND_NOW = "" -> lazyBinding is off
	// if LD_BIND_NOW = "nope" or LD_BIND_NOW is nonexistant -> lazyBinding is on
	std::map<std::string, std::string> configEnv = {
	                                            {"LD_LIBRARY_PATH", ""},
	                                            {"LD_PRELOAD", ""},
	                                            {"LD_BIND_NOW", "nope"}};
	errors += val->checkEnvironment(configEnv);

	// abort if starting state couldn't be verified
	if(errors > 0){
		std::cout
#ifdef DUMP
	<< COLOR_RED
#endif
	<< "Initial integrity of environment could not be verified! Aborting..."
#ifdef DUMP
	<< COLOR_NORM
#endif
	<< std::endl;
	}

	/*
	// extract heap for fun
	std::vector<uint8_t> buf = val->getHeapContent(vmi, pid, 0x2000);
	printHexDump(&buf);
	*/

	// check gathered pages
	std::cout << "Starting page validation ..." << std::endl;

	for ( auto page : executablePageMap){
	errors += val->validatePage(page.second, pid);
	}

	std::cout << std::endl << std::setw(7) << std::setfill('-') << ""
	<< std::endl << COLOR_BOLD << "RESULT:" << COLOR_BOLD_OFF
	<< std::endl << std::setw(7) << std::setfill('-') << "" << std::endl;

	if(errors == 0){
		std::cout << COLOR_GREEN << "No mutations found, binary clear < ^.^ >"
				  << std::endl << COLOR_NORM;
	}
	else{
		std::cout << COLOR_YELLOW << std::dec << "Found " << errors
		<< " mutations < O.o >" << COLOR_NORM << std::endl;
	}
	vmi->destroyMap(executablePageMap);
}

const char * helpString = R"EOF(
	Usage: %s [options]

	Whereby the options are:

	-h, --help
		Display the help page.

	--hypervisor_kvm
	--hypervisor_xen
	--hypervisor_file
		Use KVM, XEN, or FILE as the VM Backend the default is autodetect

	-g, --guest=<guest(File)>
		Analyse guest(File)

	-l, --loop
		Run introspection component until external interrupt.

	-k, --checkKernel=<kernelDir>
		Check for kernel integrity. Use binaries in <kernelDir> as
	   	trusted reference.

	-c, --disableCodeValidation
		Disable CodeValidation Component. Enabled by default.

	-e, --disablePointerExam
		Disable Pointer Examination. Enabled by default.

	-t, --targetsFile=<targets>
		Use call targets in <targets> for stackvalidation.

	-u, --checkUserspace=<binaryName>
		Check userspace process for integrity. Load binary <binaryName>
		as trusted reference.

	-p, --pid=<pid>
		Check <pid> for integrity

	-l, --libraryPath=<libraryPath>
		Use <libraryPath> to load trusted libraries.
)EOF";

void displayHelp(const char* argv0){
	printf(helpString, argv0);
}

int main (int argc, char **argv)
{	
	
	std::cout << COLOR_RESET;
    VMIInstance *vmi;

    //Parse options from cmdline
	std::string vmPath;
	int hypflag = 0;
	bool loopMode = false;
	
	std::string kerndir;
	bool codeValidation = true;
	bool pointerExamination = true;
	std::string targetsFile;

	std::string libraryDir;
	std::string binaryName;
	uint32_t pid = 0;
	
	int c;

	opterr = 0;

	int option_index = 0;
	static struct option long_options[] = {
		{"help",                  no_argument,       0, 'h'},
		{"hypervisor_kvm",        no_argument,       &hypflag,  VMI_KVM },
		{"hypervisor_xen",        no_argument,       &hypflag,  VMI_XEN },
		{"hypervisor_file",       no_argument,       &hypflag,  VMI_FILE },
		{"guest(File)",           required_argument, 0, 'g'},
		{"loop",                  no_argument,       0, 'l'},

		{"checkKernel",           required_argument, 0, 'k'},
		{"codeValidation",        no_argument,       0, 'c'},
		{"pointerExamination",    no_argument,       0, 'e'},
		{"targetsFile",           required_argument, 0, 't'},

		{"checkUserspace",        required_argument, 0, 'u'},
		{"pid",                   required_argument, 0, 'p'},
		{"libraryPath",           required_argument, 0, 'b'},
		{0,                       0,                 0,  0 }
	};

	while ((c = getopt_long(argc, argv, ":hg:lk:cet:u:p:b:",
					long_options, &option_index)) != -1)
		switch (c)
		{
			case 0:
				break;
			//general options
			case 'h':
				std::cout << "Showing help as requested..." << std::endl;
				displayHelp(argv[0]);
				return 0;
				break;
			case 'g':
				vmPath.assign(optarg);
				break;
			case 'l':
				loopMode = true;
				break;
			case 'k':
				kerndir.assign(optarg);
				break;
			case 'c':
				codeValidation = false;
				break;
			case 'e':
				pointerExamination = false;
				break;
			case 't':
				targetsFile.assign(optarg);
				break;
			case 'p':
				char* endptr;
				pid = strtol(optarg, &endptr, 10);
				if((errno == ERANGE)
					|| (errno != 0 && pid == 0)) {
						std::cout << "Entered pid value is invalid.";
					return 1;
				}
				if(endptr == optarg){
					std::cout << "No digit found in specified pid." << std::endl;
					return 1;
				}
				break;

			case 'u':
				binaryName.assign(optarg);
				break;

			case 'b':
				libraryDir.assign(optarg);
				break;

			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
			default:
				displayHelp(argv[0]);
				return 1;
		}
	
	if (hypflag == 0){
		hypflag = VMI_AUTO;
	}

	if(vmPath.empty()){
		vmPath.assign("insight");
	}

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	
	vmi = new VMIInstance(vmPath, hypflag | VMI_INIT_COMPLETE);
	
	if(kerndir.empty()){
		assert(false);
	}

	if (kerndir.empty() || !fexists(kerndir)) {
		std::cout << COLOR_RED << COLOR_BOLD <<
			"Wrong Path given for Kernel Directory: " <<
			kerndir << COLOR_RESET << std::endl;
		exit(0);
	}

	if(!binaryName.empty() && pid != 0){
		if (!fexists(binaryName)) {
			std::cout << COLOR_RED << COLOR_BOLD <<
				"Binary does not exist: " <<
				binaryName << COLOR_RESET << std::endl;
			exit(0);
		}
		if (!fexists(libraryDir)) {
			std::cout << COLOR_RED << COLOR_BOLD <<
				"Library Dir does not exist: " <<
				libraryDir << COLOR_RESET << std::endl;
			exit(0);
		}
	}
	
	std::cout << COLOR_GREEN << "Loading Kernel" << COLOR_NORM << std::endl;
	ElfKernelLoader* kl = KernelValidator::loadKernel(kerndir);
	kl->setVMIInstance(vmi);
	
	if(false /* option to validate kernel */){

		if (!fexists(targetsFile)) {
			std::cout << COLOR_RED << COLOR_BOLD <<
				"Wrong Path given for Targets File: " <<
				targetsFile << COLOR_RESET << std::endl;
			exit(0);
		}
		
		KernelValidator *val = new KernelValidator(kl, vmi, targetsFile);
		val->setOptions(loopMode, codeValidation, pointerExamination);
		std::cout << "Starting Kernel Validation" << std::endl;
		validateKernel(val);
	}
	
	if(!binaryName.empty() && pid != 0){
		
		// Ensure that all arguments make sense at this point
		std::cout << "Starting Process Validation..." << std::endl;
		kl->setLibraryDir(libraryDir);
		ProcessValidator *val = new ProcessValidator(kl, binaryName, vmi,
		                                         pid);
		UNUSED(val);
		//validateUserspace(val, vmi, pid);
	}
}

