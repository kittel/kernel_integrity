#include "kernint.h"

#include <cassert>
#include <typeinfo>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include <csignal>
#include <chrono>
#include <getopt.h>
#include <memory>

#include "elfkernelloader.h"
#include "kernelvalidator.h"
#include "processvalidator.h"
#include "process.h"

#include <boost/filesystem.hpp>
namespace fs = boost::filesystem;


// TODO: move stuff out of here
using namespace kernint;


// used in the signal handler
KernelValidator *validator = nullptr;

void validateKernel(KernelValidator *val) {
	const auto time_start = std::chrono::system_clock::now();
	uint64_t iterations = val->validatePages();
	const auto time_stop = std::chrono::system_clock::now();
	const auto d_actual =
	    std::chrono::duration_cast<std::chrono::milliseconds>
	        (time_stop - time_start).count();

	std::cout << "Executed " << iterations << " iterations in " << d_actual
	          << " ms ( " << (((double)d_actual) / iterations)
	          << " ms/iteration) " << std::endl;
}

void validateUserspace(ProcessValidator *val) {
	// whitelisted values for environment
	// if LD_BIND_NOW = "" -> lazyBinding is off
	// if LD_BIND_NOW = "nope" or LD_BIND_NOW is nonexistant -> lazyBinding is on
	std::map<std::string, std::string> configEnv = {
		{"LD_LIBRARY_PATH", ""},
		{"LD_PRELOAD", ""},
		{"LD_BIND_NOW", "nope"}
	};

	val->checkEnvironment(configEnv);
	val->validateProcess();
}

const char *helpString = R"EOF(
    Usage: %s [options]

    Possible options are:

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

    Note: If the guest os is mounted via sshfs the transform_symlinks
          option needs to be used!
          sshfs -o transform_symlinks <user>@<ip>:/ <dir>/
)EOF";

void displayHelp(const char *argv0) {
	printf(helpString, argv0);
}

int main(int argc, char **argv) {
	std::cout << COLOR_RESET;

	// Parse options from cmdline
	std::string vmPath;
	int hypflag   = 0;
	bool loopMode = false;

	std::string kerndir;
	bool codeValidation     = true;
	bool kernelValidation   = false;
	bool pointerExamination = true;
	bool listprocs = false;
	std::string targetsFile;

	std::string libraryDir;
	std::string rootDir;
	std::string binaryName;
	int32_t pid = 0;

	int c;

	opterr = 0;

	int option_index                    = 0;
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"hypervisor_kvm", no_argument, &hypflag, VMI_KVM},
		{"hypervisor_xen", no_argument, &hypflag, VMI_XEN},
		{"hypervisor_file", no_argument, &hypflag, VMI_FILE},
		{"guest(File)", required_argument, 0, 'g'},
		{"loop", no_argument, 0, 'l'},

		{"check-kernel", required_argument, 0, 'k'},
		{"kernel-validation", no_argument, 0, 'a'},
		{"code-validation", no_argument, 0, 'c'},
		{"pointer-examination", no_argument, 0, 'e'},
		{"targets-file", required_argument, 0, 't'},

		// TODO rethink short option characters
		{"list-procs", no_argument, 0, 'x'},
		{"check-userspace", required_argument, 0, 'u'},
		{"pid", required_argument, 0, 'p'},
		{"root-path", required_argument, 0, 'r'},
		{"library-path", required_argument, 0, 'b'},
		{0, 0, 0, 0}
	};

	while ((c = getopt_long(argc, argv, ":hg:lk:acet:xu:p:b:r:", long_options, &option_index)) != -1) {
		switch (c) {
		case 0: break;

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

		case 'a':
			kernelValidation = true;
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
			char *endptr;
			pid = strtol(optarg, &endptr, 10);
			if ((errno == ERANGE) || (errno != 0 && pid == 0)) {
				std::cout << "Entered pid value is invalid.";
				return 1;
			}
			if (endptr == optarg) {
				std::cout << "No digit found in specified pid." << std::endl;
				return 1;
			}
			break;

		case 'u':
			binaryName.assign(optarg);
			break;

		case 'r':
			rootDir.assign(optarg);
			break;

		case 'b':
			libraryDir.assign(optarg);
			break;

		case 'x':
			listprocs = true;
			break;


		case '?':
			if (isprint(optopt)) {
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			}
			else {
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			}

		default:
			displayHelp(argv[0]);
			return 1;
		}
	}

	if (rootDir.empty()){
		std::cout << "Guest root path not set, exiting ..." << std::endl;
		exit(0);
	}

	if (hypflag == 0) {
		hypflag = VMI_AUTO;
	}

	if (vmPath.empty()) {
		vmPath.assign("insight");
	}

	VMIInstance vmi(vmPath, hypflag | VMI_INIT_COMPLETE);

	if (kerndir.empty()) {
		assert(false);
	}

	if (kerndir.empty() || !fexists(kerndir)) {
		std::cout << COLOR_RED << COLOR_BOLD
		          << "Wrong Path given for Kernel Directory: " << kerndir
		          << COLOR_RESET << std::endl;
		exit(0);
	}

	if (!binaryName.empty() && pid != 0) {
		if (!fexists(binaryName)) {
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Binary does not exist: " << binaryName << COLOR_RESET
			          << std::endl;
			exit(0);
		}
		binaryName = fs::canonical(binaryName).string();
	}

	std::cout << COLOR_GREEN << "Loading Kernel" << COLOR_NORM << std::endl;

	ElfKernelLoader *kl = KernelValidator::loadKernel(kerndir);
	kl->setVMIInstance(&vmi);
	kl->initTaskManager();
	if (!rootDir.empty()) {
		while(rootDir.back() == '/') {
			rootDir.pop_back();
		}
		kl->getTaskManager()->setRootDir(rootDir);
	}

	if (!libraryDir.empty()) {
		kl->getTaskManager()->setLibraryDir(libraryDir);
	}

	if (kernelValidation) {
		if (!fexists(targetsFile)) {
			std::cout << COLOR_RED << COLOR_BOLD
			          << "Wrong Path given for Targets File: " << targetsFile
			          << COLOR_RESET << std::endl;
			exit(0);
		}

		KernelValidator val{kl, targetsFile};
		val.setOptions(loopMode, codeValidation, pointerExamination);

		validator = &val;

		auto signalHandler = [](int /*signalnumber*/) {
			if (validator) {
				validator->setOptions(false, false, false);
			}
		};

		signal(SIGINT, signalHandler);
		signal(SIGTERM, signalHandler);

		std::cout << "Starting Kernel Validation" << std::endl;
		validateKernel(&val);
	}

	if (!binaryName.empty() && pid != 0) {

		std::cout << "Creating process image to verify..." << std::endl;
		Process proc{binaryName, kl, pid};
		std::cout << "Starting process validation..." << std::endl;
		ProcessValidator val{kl, &proc, &vmi};
		validateUserspace(&val);
	}

	if (listprocs) {
		const auto time1_start = std::chrono::system_clock::now();

		std::cout << COLOR_GREEN
		          << "Starting to find kernel pointers in userspace applications"
		          << COLOR_NORM << std::endl;
		auto tasks = kl->getTaskManager()->getTasks();

		std::unordered_map<uint64_t, std::vector<std::tuple<pid_t, std::string, VMAInfo>>> physMap;

		uint64_t mapcount = 0;

		for (auto &&task : tasks) {

			static auto tm = kl->getTaskManager();

			pid_t pid = task.memberByName("pid").getValue<int64_t>();
			std::string comm = task.memberByName("comm").getValue<std::string>();

			if (tm->isKernelTask(task)) {
				continue;
			}

			std::string exe = tm->getTaskExeName(pid);

			std::cout << "Loading next process: "
			          << pid <<": " << comm << " " << exe << std::endl;

			auto VMAInfos = tm->getVMAInfo(pid);

			if (VMAInfos.size() > 0) {
				// the taskmanager must be cleaned up after each process!
				// this is because the loaded libraries depend on the
				// process environment, and they have to be loaded again!
				// otherwise, the wrong offsets will be reused!
				kl->getTaskManager()->cleanupLibraries();
				Process proc{exe, kl, pid};
				ProcessValidator val{kl, &proc, &vmi};
				validateUserspace(&val);
			}

			for (auto &&info : VMAInfos) {
				if (info.name == "[vdso]")
					continue;
				if (!(info.flags & VMAInfo::VM_READ))
					continue;
				if (!(info.flags & VMAInfo::VM_WRITE))
					continue;

				size_t mlength = (info.end - info.start) / 0x1000;
				// std::cout << "Number of pages: " << mlength << std::endl;

				for (size_t i = 0; i < mlength; i++) {
					uint64_t phys =
					vmi.translateV2P(info.start + i * 0x1000, pid);
					physMap[phys].push_back(std::make_tuple(pid, comm, info));
				}
				mapcount++;
				// info.print();
			}
		}
		std::cout << "Number of mappings in all " << tasks.size()
		          << " processes " << mapcount << std::endl;
		std::cout << "Number of different physical pages: " << physMap.size()
		          << std::endl;

		std::cout << "Starting to iterate through physical pages" << std::endl;
		int addressCount = 0;
		// const uint64_t kernelStart = 0xffffffff80000000;

		for (auto phys : physMap) {
			auto physPage = vmi.readVectorFromPA(phys.first, 0x1000);
			if (physPage.size() == 0)
				continue;
			const unsigned char *physData = physPage.data();
			for (uint16_t i = 0; i < 0x1000; i++) {
				uint64_t *physPtr = (uint64_t *)(physData + i);
				if (*physPtr == 0xffffffffffffffff)
					continue;
				// if ((*physPtr & kernelStart) != kernelStart) continue;
				// if (*physPtr > kernelStart + 0x10000000) continue;
				if (!kl->isCodeAddress(*physPtr) ||
				    kl->isDataAddress(*physPtr)) {
					continue;
				}
				addressCount++;

				std::cout << "Found address with the correct start: "
				          << std::hex << *(uint64_t *)(physData + i) << std::dec
				          << std::endl;
				for (auto &&mapping : phys.second) {
					std::cout << "Mapped into PID: " << std::get<0>(mapping)
					          << " " << std::get<1>(mapping) << std::endl;
					std::get<2>(mapping).print();
				}
			}
		}
		std::cout << std::endl
		          << "Done iterating through physical pages" << std::endl;
		std::cout << "Found " << addressCount
		          << " address with the correct start" << std::endl;

		const auto time1_stop = std::chrono::system_clock::now();
		const auto time1 = std::chrono::duration_cast<std::chrono::milliseconds>(time1_stop - time1_start).count();

		std::cout << "Needed " << time1 << " ms " << std::endl;
	}
}
