#include "paravirt_state.h"

#include "elfkernelloader.h"
#include "kernel_headers.h"
#include "libdwarfparser/function.h"
#include "libdwarfparser/structured.h"
#include "libdwarfparser/variable.h"


ParavirtState::ParavirtState(Kernel *kernel)
	:
	kernel{kernel} {}

void ParavirtState::updateState() {
	// get the current cpu architecture to adapt nops
	Instance ideal_nops_instance = this->kernel->symbols.findVariableByName("ideal_nops")->getInstance();
	uint64_t p6_address = this->kernel->symbols.findVariableByName("p6_nops")->getInstance().getAddress();
	uint64_t k8_address = this->kernel->symbols.findVariableByName("k8_nops")->getInstance().getAddress();

	uint64_t nopaddr = ideal_nops_instance.getRawValue<uint64_t>(false);

	if (nopaddr == p6_address) {
		this->ideal_nops = p6_nops;
	} else if (nopaddr == k8_address) {
		this->ideal_nops = k8_nops;
	}

	std::unordered_map<Instance *, std::string> pv_ops = {
		{&this->pv_init_ops, "pv_init_ops"},
		{&this->pv_time_ops, "pv_time_ops"},
		{&this->pv_cpu_ops, "pv_cpu_ops"},
		{&this->pv_irq_ops, "pv_irq_ops"},
		{&this->pv_apic_ops, "pv_apic_ops"},
		{&this->pv_mmu_ops, "pv_mmu_ops"},
		{&this->pv_lock_ops, "pv_lock_ops"},
	};

	for (auto &it : pv_ops) {
		Variable *var = this->kernel->symbols.findVariableByName(it.second);
		if(var){
			*it.first = var->getInstance();
		}
	}

	std::unordered_map<uint64_t *, std::string> pv_funcs = {
		{&this->nopFuncAddress, "_paravirt_nop"},
		{&this->ident32NopFuncAddress, "_paravirt_ident_32"},
		{&this->ident64NopFuncAddress, "_paravirt_ident_64"},
	};

	for (auto &it : pv_funcs) {
		Function *func = this->kernel->symbols.findFunctionByName(it.second);
		assert(func);
		*it.first = func->getAddress();
		assert(*it.first);
	}

	const Structured *pptS = dynamic_cast<const Structured*>(
		this->kernel->symbols.findBaseTypeByName("paravirt_patch_template"));
	assert(pptS);

	this->pv_irq_opsOffset = pptS->memberOffset("pv_irq_ops");
	this->pv_cpu_opsOffset = pptS->memberOffset("pv_cpu_ops");
	this->pv_mmu_opsOffset = pptS->memberOffset("pv_mmu_ops");
}
