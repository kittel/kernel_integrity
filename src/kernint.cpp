#include <cassert>
#include <typeinfo>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <csignal>

#include <kernelvalidator.h>

void signalHandler( int signum ){
	UNUSED(signum);
	KernelValidator::getInstance()->setOptions(false, false, false);  
}


int main (int argc, char **argv)
{	
	
	std::cout << COLOR_RESET;
    VMIInstance *vmi;

    //Parse options from cmdline
	const char* guestvm = NULL;
	const char* kerndir = NULL;
	int hypflag = 0;
	bool loopMode = false;
	bool codeValidation = true;
	bool pointerExamination = true;
	std::string targetsFile = std::string("");
	int index;
	int c;

	opterr = 0;

	while ((c = getopt (argc, argv, ":kxflcdt:")) != -1)
		switch (c)
		{
			case 'k':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_KVM;
				break;
			case 'x':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_XEN;
				break;
			case 'f':
				if(hypflag != 0){
					std::cout << "Could not set multiple hypervisors." <<
					   " Exiting..." << std::endl;
					return 0;
				}
				hypflag = VMI_FILE;
				break;
			case 'l':
				loopMode = true;
				break;
			case 'c':
				codeValidation = true;
				break;
			case 'd':
				pointerExamination = true;
				break;
			case 't':
				targetsFile = std::string(optarg);
				break;
			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr,
							"Unknown option character `\\x%x'.\n",
							optopt);
			default:
				printf("Usage: %s [-x|-k|-f] " \
					   "[-l] [-c] [-d] " \
					   "[-t targetsFile] " \
					   "<kerneldir> [ramdump]\n",
					   argv[0]);
				printf("\n");
				printf("\t-x\tUse XEN  as VM Backend\n");
				printf("\t-k\tUse KVM  as VM Backend\n");
				printf("\t-f\tUse FILE as VM Backend\n");
				printf("\t\tIf none of this is set LibVMI will try to autodetect the mode.\n");
				printf("\n");
				printf("\t-l\tENABLE  loop mode\n");
				printf("\t-c\tDISABLE code validation\n");
				printf("\t-d\tDISABLE pointer examination\n");
				printf("\n");
				printf("\t-t targetsFile\tLBR generated call targets\n");
				printf("\n");
				return 1;
		}
	
	if (hypflag == 0){
		hypflag = VMI_AUTO;
	}

	index = optind;

	kerndir = argv[index++];
	if(index < argc){
		guestvm = argv[index];
	} else {
		guestvm = "insight";
		hypflag = VMI_AUTO;
	}

	signal(SIGINT, signalHandler);
	signal(SIGTERM, signalHandler);
	
	vmi = new VMIInstance(guestvm, hypflag | VMI_INIT_COMPLETE);

	KernelValidator *val = new KernelValidator(kerndir, vmi, targetsFile);

	val->setOptions(loopMode, codeValidation, pointerExamination);

	val->validatePages();

}

