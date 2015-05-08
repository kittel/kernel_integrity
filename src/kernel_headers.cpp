#include "kernel_headers.h"

#include <inttypes.h>

const unsigned char p6nops[] =
{
        P6_NOP1,
        P6_NOP2,
        P6_NOP3,
        P6_NOP4,
        P6_NOP5,
        P6_NOP6,
        P6_NOP7,
        P6_NOP8,
        P6_NOP5_ATOMIC
};

const unsigned char k8nops[] =
{
        K8_NOP1,
        K8_NOP2,
        K8_NOP3,
        K8_NOP4,
        K8_NOP5,
        K8_NOP6,
        K8_NOP7,
        K8_NOP8,
        K8_NOP5_ATOMIC
};

const unsigned char * const p6_nops[ASM_NOP_MAX+2] =
{
        0, //NULL
        p6nops,
        p6nops + 1,
        p6nops + 1 + 2,
        p6nops + 1 + 2 + 3,
        p6nops + 1 + 2 + 3 + 4,
        p6nops + 1 + 2 + 3 + 4 + 5,
        p6nops + 1 + 2 + 3 + 4 + 5 + 6,
        p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
        p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};

const unsigned char * const k8_nops[ASM_NOP_MAX+2] =
{
		0, //NULL
        k8nops,
        k8nops + 1,
        k8nops + 1 + 2,
        k8nops + 1 + 2 + 3,
        k8nops + 1 + 2 + 3 + 4,
        k8nops + 1 + 2 + 3 + 4 + 5,
        k8nops + 1 + 2 + 3 + 4 + 5 + 6,
        k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
        k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};

/* Undefined instruction for dealing with missing ops pointers. */
const char ud2a[] = { 0x0f, 0x0b };

#include "libdwarfparser/libdwarfparser.h"

ParavirtState::ParavirtState(){
        this->updateState();
}

ParavirtState::~ParavirtState(){}

void ParavirtState::updateState(){

	Variable* pv_init_ops_var = Variable::findVariableByName("pv_init_ops");
	if(pv_init_ops_var){
		pv_init_ops = pv_init_ops_var->getInstance();
	}
	Variable* pv_time_ops_var = Variable::findVariableByName("pv_time_ops");
	if(pv_time_ops_var){
		pv_time_ops = pv_time_ops_var->getInstance();
	}
	Variable* pv_cpu_ops_var = Variable::findVariableByName("pv_cpu_ops");
	if(pv_cpu_ops_var){
		pv_cpu_ops = pv_cpu_ops_var->getInstance();
	}
	Variable* pv_irq_ops_var = Variable::findVariableByName("pv_irq_ops");
	if(pv_irq_ops_var){
		pv_irq_ops = pv_irq_ops_var->getInstance();
	}
	Variable* pv_apic_ops_var = Variable::findVariableByName("pv_apic_ops");
	if(pv_apic_ops_var){
		pv_apic_ops = pv_apic_ops_var->getInstance();
	}
	Variable* pv_mmu_ops_var = Variable::findVariableByName("pv_mmu_ops");
	if(pv_mmu_ops_var){
		pv_mmu_ops = pv_mmu_ops_var->getInstance();
	}
	Variable* pv_lock_ops_var = Variable::findVariableByName("pv_lock_ops");
	if(pv_lock_ops_var){
		pv_lock_ops = pv_lock_ops_var->getInstance();
	}

    Function* func = 0;

    func = Function::findFunctionByName("_paravirt_nop");
    assert(func);
    nopFuncAddress = func->getAddress();
    
    func = Function::findFunctionByName("_paravirt_ident_32");
    assert(func);
	ident32NopFuncAddress = func->getAddress();
    
    func = Function::findFunctionByName("_paravirt_ident_64");
    assert(func);
	ident64NopFuncAddress = func->getAddress();

	assert(nopFuncAddress);
    assert(ident32NopFuncAddress);
    assert(ident64NopFuncAddress);

    const Structured * pptS = 
        dynamic_cast<const Structured*>(
            BaseType::findBaseTypeByName("paravirt_patch_template"));
    assert(pptS);

    pv_irq_opsOffset = pptS->memberOffset("pv_irq_ops");
    pv_cpu_opsOffset = pptS->memberOffset("pv_cpu_ops");
    pv_mmu_opsOffset = pptS->memberOffset("pv_mmu_ops");
    
}



