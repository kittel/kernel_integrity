#ifndef PARAVIRT_STATE_H_
#define PARAVIRT_STATE_H_

#include "libdwarfparser/instance.h"

class Kernel;

class ParavirtState {
public:
	ParavirtState(Kernel *kernel, bool hasParavirt=true);
	virtual ~ParavirtState() = default;

	void updateState();

	const unsigned char *const *ideal_nops;

	Instance pv_init_ops;
	Instance pv_time_ops;
	Instance pv_cpu_ops;
	Instance pv_irq_ops;
	Instance pv_apic_ops;
	Instance pv_mmu_ops;
	Instance pv_lock_ops;

	uint64_t nopFuncAddress;
	uint64_t ident32NopFuncAddress;
	uint64_t ident64NopFuncAddress;

	uint32_t pv_irq_opsOffset;
	uint32_t pv_cpu_opsOffset;
	uint32_t pv_mmu_opsOffset;

	Kernel *kernel;
};

#endif
