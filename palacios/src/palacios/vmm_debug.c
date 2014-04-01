/* 
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Jack Lange <jarusl@cs.northwestern.edu> 
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Jack Lange <jarusl@cs.northwestern.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */


#include <palacios/vmm_debug.h>
#include <palacios/vmm.h>
#include <palacios/vmm_host_events.h>
#include <palacios/vm.h>
#include <palacios/vmm_decoder.h>
#include <palacios/vm_guest_mem.h>
#include <palacios/vmm_config.h>
#include <palacios/vmm_hypercall.h>

#define PRINT_TELEMETRY  0x00000001
#define PRINT_CORE_STATE 0x00000002
#define PRINT_ARCH_STATE 0x00000004
#define PRINT_STACK      0x00000008
#define PRINT_BACKTRACE  0x00000010
#define PRINT_PGTABLES   0x00000020

#define CLEAR_COUNTERS   0x40000000
#define SINGLE_EXIT_MODE 0x80000000 // enable single exit when this flag is set, until flag is cleared


static int 
core_handler(struct v3_core_info * core, uint32_t cmd) 
{



    if (cmd & PRINT_TELEMETRY) {
#ifdef V3_CONFIG_TELEMETRY
	v3_print_core_telemetry(core);
#endif
    }	

    if (cmd & PRINT_CORE_STATE) {
	v3_print_guest_state(core);
    }
    
    if (cmd & PRINT_ARCH_STATE) {
	v3_print_arch_state(core);
    }

    if (cmd & PRINT_STACK) {
	v3_print_stack(core);
    }

    if (cmd & PRINT_BACKTRACE) {
	v3_print_backtrace(core);
    }

    if (cmd & PRINT_PGTABLES) {
	//	v3_print_guest_pgtables(core, core->ctrl_regs.cr3);
	v3_print_guest_pg_walk(core, 0xffffffff80400000ULL, core->ctrl_regs.cr3);
    }

    return 0;
}

static int 
clear_counters(struct v3_core_info * core) 
{
    core->time_state.time_in_guest = 0;
    core->time_state.time_in_host  = 0;

    // clear telemetry
    v3_telemetry_reset(core);

    return 0;
}


static int 
evt_handler(struct v3_vm_info * vm, struct v3_debug_event * evt, void * priv_data) 
{
    int i = 0;


    v3_raise_barrier(vm, NULL);


    V3_Print("Debug Event Handler for core %d\n", evt->core_id);

 
    for (i = 0; i < vm->num_cores; i++) {
	if ((evt->core_id == i) || (evt->core_id == -1)) {

	    if (evt->cmd & CLEAR_COUNTERS) {
		clear_counters(&(vm->cores[i]));
	    }

	    core_handler(&(vm->cores[i]), evt->cmd);

	    if (evt->cmd & SINGLE_EXIT_MODE) {
		vm->cores[i].brk_exit = vm->cores[i].num_exits + 1;
	    } else {
		vm->cores[i].brk_exit = 0;
	    }
	}
    }

    v3_lower_barrier(vm);

    
    return 0;
}



static int 
debug_hcall(struct v3_core_info * core, hcall_id_t hcall_id, void * priv_data) 
{
    uint32_t cmd = core->vm_regs.rbx;

    if (cmd & CLEAR_COUNTERS) {
	clear_counters(core);
    }

    core_handler(core, cmd);
    
    return 0;
}


int 
v3_init_vm_debugging(struct v3_vm_info * vm) 
{
    v3_hook_host_event(vm, HOST_DEBUG_EVT, 
		       V3_HOST_EVENT_HANDLER(evt_handler), 
		       NULL);


    v3_register_hypercall(vm, DEBUG_CMD_HCALL, debug_hcall, NULL);

    return 0;
}





void 
v3_print_segments(struct v3_segments * segs) 
{
    struct v3_segment * seg_ptr     = (struct v3_segment *)segs;
    char              * seg_names[] = {"CS", "DS" , "ES", "FS", "GS", "SS" , "LDTR", "GDTR", "IDTR", "TR", NULL};
    int i = 0;
  
    V3_Print("Segments\n");

    for (i = 0; seg_names[i] != NULL; i++) {

	V3_Print("\t%s: Sel=%x, base=%p, limit=%x long_mode=%d, db=%d, type=%x )\n", 
		 seg_names[i], seg_ptr[i].selector, 
		 (void *)(addr_t)seg_ptr[i].base, seg_ptr[i].limit,
		 seg_ptr[i].long_mode, seg_ptr[i].db, seg_ptr[i].type);
	V3_Print("\t\tSys=%d, dpl=%x, P=%d, avail=%d, gran.=%d, unusable=%d\n", 
		 seg_ptr[i].system, seg_ptr[i].dpl, seg_ptr[i].present, 
		 seg_ptr[i].avail, seg_ptr[i].granularity, seg_ptr[i].unusable);

    }
}



void 
v3_print_ctrl_regs(struct v3_core_info * core) 
{
    struct v3_ctrl_regs * regs        = &(core->ctrl_regs);
    v3_reg_t            * reg_ptr     = (v3_reg_t *)regs;
    char                * reg_names[] = {"CR0", "CR2", "CR3", "CR4", "CR8", "FLAGS", "EFER", NULL};
    int i = 0;
   
    V3_Print("Ctrl Regs:\n");

    for (i = 0; reg_names[i] != NULL; i++) {
	V3_Print("\t%s=0x%p (at %p)\n", reg_names[i], (void *)(addr_t)reg_ptr[i], &(reg_ptr[i]));  
    }


}

#if 0
static int 
safe_gva_to_hva(struct v3_core_info * core, addr_t linear_addr, addr_t * host_addr) 
{
    /* select the proper translation based on guest mode */
    if (core->mem_mode == PHYSICAL_MEM) {
    	if (v3_gpa_to_hva(core, linear_addr, host_addr) == -1) return -1;
    } else if (core->mem_mode == VIRTUAL_MEM) {
	if (v3_gva_to_hva(core, linear_addr, host_addr) == -1) return -1;
    }
    return 0;
}

static int 
v3_print_disassembly(struct v3_core_info * core) 
{
    int passed_rip = 0;
    addr_t rip, rip_linear, rip_host;

    /* we don't know where the instructions preceding RIP start, so we just take
     * a guess and hope the instruction stream synced up with our disassembly
     * some time before RIP; if it has not we correct RIP at that point
     */

    /* start disassembly 64 bytes before current RIP, continue 32 bytes after */
    rip = (addr_t) core->rip - 64;
    while ((int) (rip - core->rip) < 32) {
	V3_Print("disassembly step\n");

    	/* always print RIP, even if the instructions before were bad */
    	if (!passed_rip && rip >= core->rip) {
    	    if (rip != core->rip) {
    	    	V3_Print("***** bad disassembly up to this point *****\n");
    	    	rip = core->rip;
    	    }
    	    passed_rip = 1;
    	}

    	/* look up host virtual address for this instruction */
    	rip_linear = get_addr_linear(core, rip, V3_SEG_CS);
    	if (safe_gva_to_hva(core, rip_linear, &rip_host) < 0) {
    	    rip++;
    	    continue;
    	}

    	/* print disassembled instrcution (updates rip) */
    	if (v3_disasm(core, (void *) rip_host, &rip, rip == core->rip) < 0) {
    	    rip++;
    	    continue;
    	}

    }

    return 0;
}

#endif

void 
v3_print_guest_state(struct v3_core_info * core) 
{
    addr_t linear_addr = 0; 
    addr_t host_addr   = 0;
    int ret = 0;


    V3_Print("=========================================\n");
    V3_Print("=========================================\n");
    V3_Print("Guest state for Core %d\n", core->vcpu_id);
    V3_Print("=========================================\n");


    V3_Print("RIP: %p\n", (void *)(addr_t)(core->rip));

    linear_addr = get_addr_linear(core, core->rip, V3_SEG_CS);
    V3_Print("RIP Linear: %p\n", (void *)linear_addr);

    V3_Print("NumExits: %u\n", (uint32_t)core->num_exits);

    V3_Print("IRQ STATE: started=%d, pending=%d\n", 
	     core->intr_core_state.irq_started, 
	     core->intr_core_state.irq_pending);
    V3_Print("EXCP STATE: err_code_valid=%d, err_code=%x\n", 
	     core->excp_state.excp_error_code_valid, 
	     core->excp_state.excp_error_code);


    v3_print_segments(&(core->segments));
    v3_print_ctrl_regs(core);

    if (core->shdw_pg_mode == SHADOW_PAGING) {
	V3_Print("Shadow Paging Guest Registers:\n");
	V3_Print("\tGuest CR0=%p\n", (void *)(addr_t)(core->shdw_pg_state.guest_cr0));
	V3_Print("\tGuest CR3=%p\n", (void *)(addr_t)(core->shdw_pg_state.guest_cr3));
	V3_Print("\tGuest EFER=%p\n", (void *)(addr_t)(core->shdw_pg_state.guest_efer.value));
	// CR4
    }
    v3_print_GPRs(core);

    v3_print_mem_map(core->vm_info);

    if (core->mem_mode == PHYSICAL_MEM) {
	ret = v3_gpa_to_hva(core, linear_addr, &host_addr);
    } else if (core->mem_mode == VIRTUAL_MEM) {
	ret = v3_gva_to_hva(core, linear_addr, &host_addr);
    }

    

    if (ret == 0) {
	V3_Print("Core %u: Instr (15 bytes) at %p:\n", core->vcpu_id, (void *)host_addr);
	
	v3_dump_mem((uint8_t *)host_addr - 15, 15);
	V3_Print("Instruction Ptr here:\n");
	v3_dump_mem((uint8_t *)host_addr, 15);
    } else {
	PrintError("Error could not get host address of RIP (linear_addr=%p)\n", (void *)linear_addr);
    }

    v3_print_stack(core);

    V3_Print("Guest Kernel Backtrace\n");
    v3_print_backtrace(core);

       //  v3_print_disassembly(core);



    V3_Print("=========================================\n");
    V3_Print("FINISHED CORE STATE for CORE %d\n", core->vcpu_id);
    V3_Print("=========================================\n");
    V3_Print("=========================================\n");
}



#include <palacios/vmcb.h>
#include <palacios/vmcs.h>

#include <palacios/vmm_msr.h>
#include <palacios/vmm_lowlevel.h>
void 
v3_print_arch_state(struct v3_core_info * core) 
{
    extern v3_cpu_arch_t v3_mach_type;


    V3_Print("=========================================\n");
    V3_Print("=========================================\n");
    V3_Print("Arch state for Core %d\n", core->vcpu_id);
    V3_Print("=========================================\n");

    switch (v3_mach_type) {
#ifdef V3_CONFIG_SVM
        case V3_SVM_CPU:
        case V3_SVM_REV3_CPU:
	    PrintDebugVMCB(core->vmm_data);
            break;
#endif
#ifdef V3_CONFIG_VMX
        case V3_VMX_CPU:
        case V3_VMX_EPT_CPU:
        case V3_VMX_EPT_UG_CPU:
	    V3_Call_On_CPU(core->pcpu_id, v3_print_vmcs, NULL);
            break;
#endif
        default:
            PrintError("Invalid CPU Type 0x%x\n", v3_mach_type);
            return;
    }

    V3_Print("=========================================\n");
    V3_Print("FINISHED ARCH STATE for CORE %d\n", core->vcpu_id);
    V3_Print("=========================================\n");
    V3_Print("=========================================\n");

}


void 
v3_print_guest_state_all(struct v3_vm_info * vm) 
{
    int i = 0;

    V3_Print("=========================================\n");
    V3_Print("VM Core states for %s\n", vm->name);
    V3_Print("=========================================\n");


    for (i = 0; i < 80; i++) {
	V3_Print("-");
    }

    for (i = 0; i < vm->num_cores; i++) {
	v3_print_guest_state(&vm->cores[i]);  
    }
    
    for (i = 0; i < 80; i++) {
	V3_Print("-");
    }

    V3_Print("\n");    
}



void 
v3_print_stack(struct v3_core_info * core) 
{
    addr_t        linear_addr = 0;
    addr_t        host_addr   = 0;
    v3_cpu_mode_t cpu_mode    = v3_get_vm_cpu_mode(core);
    int i = 0;



    V3_Print("=========================================\n");
    V3_Print("Stack Trace for Core %d\n", core->vcpu_id);
    V3_Print("=========================================\n");

    linear_addr = get_addr_linear(core, core->vm_regs.rsp, V3_SEG_SS);
 
    V3_Print("Stack at %p:\n", (void *)linear_addr);
   
    if (core->mem_mode == PHYSICAL_MEM) {
	if (v3_gpa_to_hva(core, linear_addr, &host_addr) == -1) {
	    PrintError("Could not translate Stack address\n");
	    return;
	}
    } else if (core->mem_mode == VIRTUAL_MEM) {
	if (v3_gva_to_hva(core, linear_addr, &host_addr) == -1) {
	    PrintError("Could not translate Virtual Stack address\n");
	    return;
	}
    }
    
    V3_Print("Host Address of rsp = 0x%p\n", (void *)host_addr);
 
    // We start i at one because the current stack pointer points to an unused stack element
    for (i = 0; i <= 24; i++) {

	if (cpu_mode == REAL) {
	    V3_Print("\t0x%.4x\n", *((uint16_t *)host_addr + (i * 2)));
	} else if (cpu_mode == LONG) {
	    V3_Print("\t%p\n", (void *)*(addr_t *)(host_addr + (i * 8)));
	} else {
	    // 32 bit stacks...
	    V3_Print("\t0x%.8x\n", *(uint32_t *)(host_addr + (i * 4)));
	}
    }


    V3_Print("=========================================\n");
    V3_Print("FINISHED STACK TRACE for CORE %d\n", core->vcpu_id);
    V3_Print("=========================================\n");

}    


void 
v3_print_backtrace(struct v3_core_info * core) 
{
    struct v3_cfg_file * system_map = v3_cfg_get_file(core->vm_info, "System.map");
    v3_cpu_mode_t        cpu_mode   = v3_get_vm_cpu_mode(core);
    addr_t               gla_rbp    = 0;
    int i = 0;

    V3_Print("=========================================\n");
    V3_Print("=========================================\n");
    V3_Print("Performing Backtrace for Core %d\n", core->vcpu_id);
    V3_Print("=========================================\n");
    V3_Print("\tRSP=%p, RBP=%p\n", (void *)core->vm_regs.rsp, (void *)core->vm_regs.rbp);

    gla_rbp = get_addr_linear(core, core->vm_regs.rbp, V3_SEG_SS);


    for (i = 0; i < 30; i++) {
	addr_t hva_rbp  = 0; 
	addr_t hva_rip  = 0; 
	char * sym_name = NULL;
	addr_t rip_val  = 0;

	if (core->mem_mode == PHYSICAL_MEM) {
	    if (v3_gpa_to_hva(core, gla_rbp, &hva_rbp) == -1) {
		PrintError("Could not translate Stack address\n");
		return;
	    }
	} else if (core->mem_mode == VIRTUAL_MEM) {
	    if (v3_gva_to_hva(core, gla_rbp, &hva_rbp) == -1) {
		PrintError("Could not translate Virtual Stack address\n");
		return;
	    }
	}


	hva_rip = hva_rbp + v3_get_addr_width(core);
	
	if (cpu_mode == REAL) {
	    rip_val = (addr_t)*(uint16_t *)hva_rip;
	} else if (cpu_mode == LONG) {
	    rip_val = (addr_t)*(uint64_t *)hva_rip;
	} else {
	    rip_val = (addr_t)*(uint32_t *)hva_rip;
	}

	if (system_map) {
	    char   * tmp_ptr     = system_map->data;
	    char   * sym_ptr     = NULL;
	    uint64_t file_offset = 0; 
	    uint64_t sym_offset  = 0;

	    while (file_offset < system_map->size) {
		sym_offset = strtox(tmp_ptr, &tmp_ptr);

		tmp_ptr += 3; // pass over symbol type

		if (sym_offset > rip_val) {
		    char * end_ptr = strchr(sym_ptr, '\n');

		    if (end_ptr) {
			*end_ptr = 0; // null terminate symbol...
		    }

		    sym_name = sym_ptr;
		    break;
		}

		sym_ptr = tmp_ptr;
		{ 
		    char * end_ptr2 = strchr(tmp_ptr, '\n');

		    if (!end_ptr2) {
			tmp_ptr += strlen(tmp_ptr) + 1;
		    } else {
			tmp_ptr = end_ptr2 + 1;
		    }
		}
	    }
	}

	if (!sym_name) {
	    sym_name = "?";
	}

	if (cpu_mode == REAL) {
	    V3_Print("Next RBP=0x%.4x, RIP=0x%.4x (%s)\n", 
		     *(uint16_t *)hva_rbp,*(uint16_t *)hva_rip, 
		     sym_name);
	    
	    gla_rbp = *(uint16_t *)hva_rbp;
	} else if (cpu_mode == LONG) {
	    V3_Print("Next RBP=%p, RIP=%p (%s)\n", 
		     (void *)*(uint64_t *)hva_rbp, (void *)*(uint64_t *)hva_rip,
		     sym_name);
	    gla_rbp = *(uint64_t *)hva_rbp;
	} else {
	    V3_Print("Next RBP=0x%.8x, RIP=0x%.8x (%s)\n", 
		     *(uint32_t *)hva_rbp, *(uint32_t *)hva_rip,
		     sym_name);
	    gla_rbp = *(uint32_t *)hva_rbp;
	}

    }

    V3_Print("=========================================\n");
    V3_Print("=========================================\n");


}


#ifdef __V3_32BIT__

void 
v3_print_GPRs(struct v3_core_info * core) 
{
    struct v3_gprs * regs        = &(core->vm_regs);
    v3_reg_t       * reg_ptr     = (v3_reg_t *)regs;
    char           * reg_names[] = { "RDI", "RSI", "RBP", "RSP", "RBX", "RDX", "RCX", "RAX", NULL};
    int i = 0;

    V3_Print("32 bit GPRs:\n");

    for (i = 0; reg_names[i] != NULL; i++) {
	V3_Print("\t%s=0x%p (at %p)\n", reg_names[i], (void *)(addr_t)reg_ptr[i], &(reg_ptr[i]));  
    }
}

#elif __V3_64BIT__

void 
v3_print_GPRs(struct v3_core_info * core) 
{
    struct v3_gprs * regs        = &(core->vm_regs);
    v3_reg_t       * reg_ptr     = (v3_reg_t *)regs;
    char           * reg_names[] = { "RDI", "RSI", "RBP", "RSP", "RBX", "RDX", "RCX", "RAX", \
				     "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", NULL};
    int i = 0;


    V3_Print("64 bit GPRs:\n");

    for (i = 0; reg_names[i] != NULL; i++) {
	V3_Print("\t%s=0x%p (at %p)\n", reg_names[i], (void *)(addr_t)reg_ptr[i], &(reg_ptr[i]));  
    }
}

#endif
