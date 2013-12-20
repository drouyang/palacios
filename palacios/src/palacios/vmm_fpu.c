/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2013, Jack Lange <jacklange@cs.pitt.edu> 
 * Copyright (c) 2013, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jacklange@cs.pitt.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmm.h>
#include <palacios/vmm_ctrl_regs.h>

#include <palacios/vmm_telemetry.h>

#include <palacios/vmm_fpu.h>


#define XSETBV ".byte 0x0f,0x01,0xd1;"  
#define XGETBV ".byte 0x0f,0x01,0xd0;"

extern v3_cpu_arch_t v3_cpu_types[];

static inline addr_t get_cr0() {
    addr_t cr0 = 0;

    __asm__ __volatile__ ( "movq    %%cr0, %0; "
                           : "=q"(cr0)
                           :
    );


    return cr0;
}



static inline addr_t get_cr4() {
    addr_t cr4 = 0;

    __asm__ __volatile__ ( "movq    %%cr4, %0; "
                           : "=q"(cr4)
                           :
    );


    return cr4;
}



static inline uint64_t xgetbv() {
    uint32_t eax = 0;
    uint32_t edx = 0;
    uint32_t index = 0;

    __asm__ __volatile__ (XGETBV
			  : "=a"(eax), "=d"(edx)
			  : "c"(index)
			  );


    return  eax + ((uint64_t)edx << 32);

}


static inline void xsetbv(uint64_t value) {
    uint32_t eax = value;
    uint32_t edx = value >> 32;
    uint32_t index = 0;

    __asm__ __volatile__ (XSETBV
			  :
			  : "a"(eax), "d"(edx), "c"(index)
			  );
}



#ifdef V3_CONFIG_VMX
#include <palacios/vmcs.h>
#include <palacios/vmx.h>
#include <palacios/vmx_lowlevel.h>

#define CR0_TS 0x00000008
#define CR0_MP 0x00000002

static int vmx_disable_fpu_exits(struct guest_info * core) {
    struct vmx_data * vmx_state = (struct vmx_data *)core->vmm_data;
    struct cr0_32 * cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);
    struct cr0_32 * guest_cr0 = (struct cr0_32 *)&(core->shdw_pg_state.guest_cr0);
    addr_t cr0_mask = 0;
    int vmx_ret = 0;

    vmx_state->excp_bmap.nm = 0;
    vmx_ret |= check_vmcs_write(VMCS_EXCP_BITMAP, vmx_state->excp_bmap.value);

    cr0->ts = guest_cr0->ts;
    cr0->mp = guest_cr0->mp;

    vmx_ret |= check_vmcs_read(VMCS_CR0_MASK, &cr0_mask);
    cr0_mask &= ~(CR0_TS);
    vmx_ret |= check_vmcs_write(VMCS_CR0_MASK, cr0_mask);

    return vmx_ret;
}

static int vmx_enable_fpu_exits(struct guest_info * core) {
    struct vmx_data * vmx_state = (struct vmx_data *)core->vmm_data;
    struct cr0_32 * cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);
    int vmx_ret = 0;
    addr_t cr0_mask = 0;

    vmx_state->excp_bmap.nm = 1;
    vmx_ret |= check_vmcs_write(VMCS_EXCP_BITMAP, vmx_state->excp_bmap.value);

    cr0->ts = 1;
    cr0->mp = 1;

    vmx_ret |= check_vmcs_read(VMCS_CR0_MASK, &cr0_mask);
    cr0_mask |= (CR0_TS);
    vmx_ret |= check_vmcs_write(VMCS_CR0_MASK, cr0_mask);

    return vmx_ret;
}
#endif

#ifdef V3_CONFIG_SVM
#include <palacios/svm.h>
#include <palacios/vmcb.h>

static int svm_disable_fpu_exits(struct guest_info * core) {
    struct cr0_32 * cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);
    struct cr0_32 * guest_cr0 = (struct cr0_32 *)&(core->shdw_pg_state.guest_cr0);
    vmcb_ctrl_t * ctrl_area = GET_VMCB_CTRL_AREA((vmcb_t *)(core->vmm_data));

    ctrl_area->exceptions.nm = 0;
    *cr0 = *guest_cr0;

    if (core->shdw_pg_mode == NESTED_PAGING) {
	ctrl_area->cr_reads.cr0 = 0;
	ctrl_area->cr_writes.cr0 = 0;
    } else {
	/* Fix up Shadow CR0 fields based on SHADOW PAGING requirements */
	/* See handle_mov_to_cr0 in vmm_ctrl_regs.c */

	cr0->pg = 1;

	if (guest_cr0->pg == 0) {
	    cr0->wp = 1;
	}
    }

    return 0;

}

static int svm_enable_fpu_exits(struct guest_info * core) {
    struct cr0_32 * cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);
    struct cr0_32 * guest_cr0 = (struct cr0_32 *)&(core->shdw_pg_state.guest_cr0);
    vmcb_ctrl_t * ctrl_area = GET_VMCB_CTRL_AREA((vmcb_t *)(core->vmm_data));

    /* Cache current Guest CR0 value, before we modify it */
    *guest_cr0 = *cr0;

    cr0->ts = 1;
    cr0->mp = 1;

    ctrl_area->exceptions.nm = 1;

    if (core->shdw_pg_mode == NESTED_PAGING) {
	ctrl_area->cr_reads.cr0 = 1;
	ctrl_area->cr_writes.cr0 = 1;
    }

    return 0;
}

#endif


/* We assume we are running on a Machine with SSE* extensions 
 * along with the fxsave/fxrstor functionality 
 */


int v3_fpu_init(struct guest_info * core) {
    
    struct v3_fpu_state * fpu = &(core->fpu_state);
    struct v3_fpu_arch * arch_state = &(fpu->arch_state);
    addr_t host_cr4_val = get_cr4();
    struct cr4_32 * host_cr4 = (struct cr4_32 *)&host_cr4_val;
    //    struct cr4_32 * guest_cr4 = (struct cr4_32 *)&(core->ctrl_regs.cr4);

    V3_Print("Initializing FPU for core %d\n", core->vcpu_id);
    V3_Print("Host CR4 VAL=%x\n", (uint32_t)host_cr4_val);


    memset(arch_state, 0, sizeof(struct v3_fpu_arch));

    // is OSXSAVE supported 
    if (host_cr4->osxsave) {
	fpu->osxsave_enabled = 1;
	V3_Print("ENabling OSXSAVE for Guest\n");

	//	guest_cr4->osx = 1;
	v3_cpuid_add_fields(core->vm_info, 0x01, 0, 0, 0, 0, (1 << 26), (1 << 26), 0, 0);

    } else {
	// Disable XSAVE (cpuid 0x01, ECX bit 26)
	v3_cpuid_add_fields(core->vm_info, 0x01, 0, 0, 0, 0, (1 << 26), 0, 0, 0);
    }

    if (host_cr4->osf_xsr) {
	fpu->osfxsr_enabled = 1;

	//
    } else {
	// Disable FXSAVE (cpuid 0x01, EDX bit 24)
	//	v3_cpuid_add_fields(core->vm_info, 0x01, 0, 0, 0, 0, 0, 0, (1 << 24), 0);
    }

    // We enable FXSAVE in the guest, regardless of whether the host supports it
    // If the host has it disabled, then presumably there will never be a conflict
    v3_cpuid_add_fields(core->vm_info, 0x01, 0, 0, 0, 0, 0, 0, (1 << 24), (1 << 24));
    

    arch_state->cwd = 0x37f;
    arch_state->mxcsr = 0x1f80;

    if (fpu->osxsave_enabled) {
	fpu->guest_xcr0 = XCR0_INIT_STATE;
	fpu->host_xcr0 = xgetbv();
	
	
	V3_Print("Guest XCR0=%p\n", (void *)fpu->guest_xcr0);
	V3_Print("Host XCR0=%p\n", (void *)fpu->host_xcr0);
    }

    fpu->enable_fpu_exits = 1;

    V3_Print("FPU Initialized\n");

    return 0;
}


/* Executes atomically as part of the core entry procedure */
int v3_fpu_on_entry(struct guest_info * core) {
    struct v3_fpu_state * fpu = &(core->fpu_state);
    struct cr0_32 * cr0 = (struct cr0_32 *)&(core->ctrl_regs.cr0);


    if (fpu->disable_fpu_exits == 1) {

	switch (v3_cpu_types[core->vcpu_id]) {
#ifdef V3_CONFIG_VMX
	    case V3_VMX_CPU:
	    case V3_VMX_EPT_CPU:
	    case V3_VMX_EPT_UG_CPU:
		vmx_disable_fpu_exits(core);
		break;
#endif
#ifdef V3_CONFIG_SVM
	    case V3_SVM_CPU:
	    case V3_SVM_REV3_CPU:
		svm_disable_fpu_exits(core);
		break;
#endif
	    case V3_INVALID_CPU:
	    default:
		PrintError("CPU has no virtualization Extensions\n");
		break;
		
	}

	v3_telemetry_inc_core_counter(core, "FPU_EXITS_DISABLE");

	fpu->disable_fpu_exits = 0;	
	
    } else if (fpu->enable_fpu_exits == 1) {
	switch (v3_cpu_types[core->vcpu_id]) {
#ifdef V3_CONFIG_VMX
	    case V3_VMX_CPU:
	    case V3_VMX_EPT_CPU:
	    case V3_VMX_EPT_UG_CPU:
		vmx_enable_fpu_exits(core);
		break;
#endif
#ifdef V3_CONFIG_SVM
	    case V3_SVM_CPU:
	    case V3_SVM_REV3_CPU:
		svm_enable_fpu_exits(core);
		break;
#endif
	    case V3_INVALID_CPU:
	    default:
		PrintError("CPU has no virtualization Extensions\n");
		break;
	}

	fpu->enable_fpu_exits = 0;
	v3_telemetry_inc_core_counter(core, "FPU_EXITS_ENABLE");
    }

    fpu->last_ts_value = cr0->ts;
    
    return 0;
}




int v3_fpu_deactivate(struct guest_info * core) {
    struct v3_fpu_state * fpu = &(core->fpu_state);


    if (fpu->fpu_activated == 1) {

	//	V3_Print("Saving FPU state for core %d\n", core->vcpu_id);
	v3_telemetry_inc_core_counter(core, "FPU_DEACTIVATE");
	
	if (fpu->osxsave_enabled) {

	    __asm__ __volatile__ ("xsave %0\r\n"
				  : 
				  : "m"(fpu->arch_state)
				  : "memory"
				  );

	} else if (fpu->osfxsr_enabled) {

	    __asm__ __volatile__ ("fxsave %0\r\n"
				  : 
				  : "m"(fpu->arch_state)
				  : "memory"
				  );
	} else {
	    __asm__ __volatile__ ("fsave %0\r\n"
				  : 
				  : "m"(fpu->arch_state)
				  : "memory"
				  );
	}
			      

	fpu->fpu_activated = 0;
	fpu->enable_fpu_exits = 1;

	// restore host state
	V3_RestoreFPU();
    }

    if (fpu->osxsave_enabled) {
	fpu->guest_xcr0 = xgetbv();
	xsetbv(fpu->host_xcr0);
    }

 



    return 0;
}



int v3_fpu_activate(struct guest_info * core) {
    struct v3_fpu_state * fpu = &(core->fpu_state);

    // save host state
    V3_SaveFPU();

    
    fpu->fpu_activated = 1;
    fpu->disable_fpu_exits = 1;
    
    if (fpu->osxsave_enabled) {
	xsetbv(fpu->guest_xcr0);
	
	// restore state
	__asm__ __volatile__ ("xrstor %0 \r\n"
			      : 
			      : "m"(fpu->arch_state)
			      : "memory"
			      );
    } else if (fpu->osfxsr_enabled) {
	// restore state
	__asm__ __volatile__ ("fxrstor %0 \r\n"
			      : 
			      : "m"(fpu->arch_state)
			      : "memory"
			      );
    } else {
	__asm__ __volatile__ ("frstor %0 \r\n"
			      : 
			      : "m"(fpu->arch_state)
			      : "memory"
			      );
    }


    v3_telemetry_inc_core_counter(core, "FPU_ACTIVATE");


    return 0;

}



int v3_fpu_handle_xsetbv(struct guest_info * core) {
    struct v3_fpu_state * fpu = &(core->fpu_state);
    uint32_t index = core->vm_regs.rcx;


    if (index != 0) {
	PrintError("Invalid XCR (%d)\n", index);
	return -1;
    }

   if (fpu->osxsave_enabled) {
       fpu->guest_xcr0 = (uint32_t)(core->vm_regs.rax);
       fpu->guest_xcr0 += (core->vm_regs.rdx << 32);
       
       xsetbv(fpu->guest_xcr0);
   }

    core->rip += 3;

    v3_telemetry_inc_core_counter(core, "FPU_XSETBV");


    return 0;
}












/*

#ifdef __V3_64BIT__
	__asm__ __volatile__ ("movq %%cr0, %%rbx \r\n"
			      "orq  $0x8,  %%rbx \r\n"
			      "movq %%rbx, %%cr0 \r\n"
			      :
			      :
			      : "%rbx" 
			      );

#elif __V3_32BIT__
	__asm__ __volatile__ ("movl %%cr0, %%ebx \r\n"
			      "orl  $0x8,  %%ebx \r\n"
			      "movl %%ebx, %%cr0 \r\n"
			      :
			      :
			      : "%ebx" 
			      );
#endif

*/
