
/*
 * This file is part of the Palacios Virtual Machine Monitor developed
 * by the V3VEE Project with funding from the United States National 
 * Science Foundation and the Department of Energy.  
 *
 * The V3VEE Project is a joint project between Northwestern University
 * and the University of New Mexico.  You can find out more at 
 * http://www.v3vee.org
 *
 * Copyright (c) 2008, Andy Gocke <agocke@gmail.com>
 * Copyright (c) 2008, The V3VEE Project <http://www.v3vee.org> 
 * All rights reserved.
 *
 * Author: Andy Gocke <agocke@gmail.com>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "V3VEE_LICENSE".
 */

#include <palacios/vmx_ctrl_regs.h>
#include <palacios/vmm.h>
#include <palacios/vmx_lowlevel.h>
#include <palacios/vmx.h>
#include <palacios/vmx_assist.h>
#include <palacios/vm_guest_mem.h>
#include <palacios/vmm_direct_paging.h>
#include <palacios/vmm_ctrl_regs.h>
#include <palacios/vmm_fpu.h>

#ifndef V3_CONFIG_DEBUG_VMX
#undef PrintDebug
#define PrintDebug(fmt, args...)
#endif

static v3_reg_t *  get_reg_ptr(struct v3_core_info * core, struct vmx_exit_cr_qual * cr_qual);
static int   handle_mov_to_cr0(struct v3_core_info * core, v3_reg_t * new_val, struct vmx_exit_info * exit_info);
static int   handle_mov_to_cr3(struct v3_core_info * core, v3_reg_t * cr3_reg);
static int handle_mov_from_cr3(struct v3_core_info * core, v3_reg_t * cr3_reg);


int
v3_vmx_handle_cr0_access(struct v3_core_info     * core, 
			 struct vmx_exit_cr_qual * cr_qual, 
			 struct vmx_exit_info    * exit_info) 
{

    if (cr_qual->access_type < 3) {
        v3_reg_t * reg = get_reg_ptr(core, cr_qual);
        
        if (cr_qual->access_type == 0) {
	    // Mov to cr
            if (handle_mov_to_cr0(core, reg, exit_info) != 0) {
                PrintError("Could not handle CR0 write\n");
                return -1;
            }
        } else if (cr_qual->access_type == 1) {
            // Mov from cr
	    PrintError("Mov From CR0 not handled\n");
	    return -1;
        } else if (cr_qual->access_type == 2) {
	    // clts
	    struct cr0_32 * guest_cr0 = (struct cr0_32 *)&(core->shdw_pg_state.guest_cr0);
	    
	    guest_cr0->ts = 0;
	    
	    v3_fpu_activate(core);
	}

        return 0;
    }

    PrintError("Invalid CR0 Access type?? (type=%d)\n", cr_qual->access_type);
    return -1;
}

int 
v3_vmx_handle_cr3_access(struct v3_core_info     * core, 
			 struct vmx_exit_cr_qual * cr_qual) 
{

    if (cr_qual->access_type < 2) {
        v3_reg_t * reg = get_reg_ptr(core, cr_qual);

        if (cr_qual->access_type == 0) {
            return handle_mov_to_cr3(core, reg);
        } else {
            return handle_mov_from_cr3(core, reg);
        }
    }

    PrintError("Invalid CR3 Access type?? (type=%d)\n", cr_qual->access_type);
    return -1;
}

int 
v3_vmx_handle_cr4_access(struct v3_core_info     * core, 
			 struct vmx_exit_cr_qual * cr_qual) 
{
    if (cr_qual->access_type < 2) {

	if (cr_qual->access_type == 0) {
	    if (v3_handle_cr4_write(core) != 0) {
		PrintError("Could not handle CR4 write\n");
		return -1;
	    }
	    core->ctrl_regs.cr4 |= 0x2000; // no VMX allowed in guest, so mask CR4.VMXE
	} else {
	    if (v3_handle_cr4_read(core) != 0) {
		PrintError("Could not handle CR4 read\n");
		return -1;
	    }
	}

	return 0;
    }

    PrintError("Invalid CR4 Access type?? (type=%d)\n", cr_qual->access_type);
    return -1;
}

static int 
handle_mov_to_cr3(struct v3_core_info * core, 
		  v3_reg_t            * cr3_reg) 
{

    if (core->shdw_pg_mode == SHADOW_PAGING) {

	/*
        PrintDebug("Old Guest CR3=%p, Old Shadow CR3=%p\n",
		   (void *)core->ctrl_regs.cr3,
		   (void *)core->shdw_pg_state.guest_cr3);
	*/

        if (core->cpu_mode == LONG) {
            core->shdw_pg_state.guest_cr3 = (uint64_t)*cr3_reg;
        } else {
            core->shdw_pg_state.guest_cr3 = (uint32_t)*cr3_reg;
        }


        if (v3_get_vm_mem_mode(core) == VIRTUAL_MEM) {
            if (v3_activate_shadow_pt(core) == -1) {
                PrintError("Failed to activate 32 bit shadow page table\n");
                return -1;
            }
        }
	/*
        PrintDebug("New guest CR3=%p, New shadow CR3=%p\n",
		   (void *)core->ctrl_regs.cr3,
		   (void *)core->shdw_pg_state.guest_cr3);
	*/
    } else if (core->shdw_pg_mode == NESTED_PAGING) {
        PrintError("Nested paging not available in VMX right now!\n");
        return -1;
    }



    return 0;
}

static
int handle_mov_from_cr3(struct v3_core_info * core, 
			v3_reg_t            * cr3_reg) 
{
    

    if (core->shdw_pg_mode == SHADOW_PAGING) {

        if ((v3_get_vm_cpu_mode(core) == LONG) ||
	    (v3_get_vm_cpu_mode(core) == LONG_32_COMPAT)) {

            *cr3_reg = (uint64_t)core->shdw_pg_state.guest_cr3;
        } else {
            *cr3_reg = (uint32_t)core->shdw_pg_state.guest_cr3;
        }

    } else {
        PrintError("Unhandled paging mode\n");
        return -1;
    }


    return 0;
}

static int 
handle_mov_to_cr0(struct v3_core_info  * core, 
		  v3_reg_t             * new_cr0, 
		  struct vmx_exit_info * exit_info) 
{
    struct cr0_32   * guest_cr0    = (struct cr0_32   *)&(core->ctrl_regs.cr0);
    struct cr0_32   * shdw_cr0     = (struct cr0_32   *)&(core->shdw_pg_state.guest_cr0);
    struct cr0_32   * new_shdw_cr0 = (struct cr0_32   *)new_cr0;
    struct vmx_data * vmx_info     = (struct vmx_data *)core->vmm_data;
    uint_t paging_transition       = 0;
    extern v3_cpu_arch_t v3_mach_type;


    PrintDebug("Mov to CR0\n");
    PrintDebug("Old shadow CR0: 0x%x, New shadow CR0: 0x%x\n",
	       (uint32_t)core->shdw_pg_state.guest_cr0, (uint32_t)*new_cr0);

    if ((new_shdw_cr0->pe       != shdw_cr0->pe) && 
	(vmx_info->assist_state != VMXASSIST_DISABLED)) {
	/*
	  PrintDebug("Guest CR0: 0x%x\n", *(uint32_t *)guest_cr0);
	  PrintDebug("Old shadow CR0: 0x%x\n", *(uint32_t *)shdw_cr0);
	  PrintDebug("New shadow CR0: 0x%x\n", *(uint32_t *)new_shdw_cr0);
	*/

        if (v3_vmxassist_ctx_switch(core) != 0) {
            PrintError("Unable to execute VMXASSIST context switch!\n");
            return -1;
        }
	
        if (vmx_info->assist_state == VMXASSIST_ON) {
            PrintDebug("Loading VMXASSIST at RIP: %p\n", (void *)(addr_t)core->rip);
        } else {
            PrintDebug("Leaving VMXASSIST and entering protected mode at RIP: %p\n",
		       (void *)(addr_t)core->rip);
        }

	// PE switches modify the RIP directly, so we clear the instr_len field to avoid catastrophe
	exit_info->instr_len = 0;

	//	v3_vmx_restore_vmcs(core);
	//      v3_print_vmcs(core);

    } else {

	if (new_shdw_cr0->pg != shdw_cr0->pg) {
	    paging_transition = 1;
	}

	
	// Except PG, PE, and NE, which are always set
	if ((core->shdw_pg_mode == SHADOW_PAGING) ||  
	    (v3_mach_type       != V3_VMX_EPT_UG_CPU)) {
	    
	    // The shadow always reflects the new value
	    *shdw_cr0     = *new_shdw_cr0;
	    

	    // We don't care about most of the flags, so lets go for it 
	    // and set them to the guest values
	    *guest_cr0    = *shdw_cr0;
	
	    guest_cr0->pe = 1;
	    guest_cr0->pg = 1;
	} else {
	    // Unrestricted guest 
	    //    *(uint32_t *)shdw_cr0 = (0x00000020 & *(uint32_t *)new_shdw_cr0);

	    *guest_cr0    = *new_shdw_cr0;
	    guest_cr0->cd = 0;
	}

	guest_cr0->ne = 1;
	guest_cr0->et = 1;

	
	if (paging_transition) {
	    // Paging transition
	    
	    if (v3_get_vm_mem_mode(core) == VIRTUAL_MEM) {
		struct efer_64 * vm_efer = (struct efer_64 *)&(core->shdw_pg_state.guest_efer);
		struct efer_64 * hw_efer = (struct efer_64 *)&(core->ctrl_regs.efer);
		
		if (vmx_info->assist_state != VMXASSIST_DISABLED) {
		    if (vm_efer->lme) {
			PrintDebug("Enabling long mode\n");
			
			hw_efer->lma = 1;
			hw_efer->lme = 1;
			vmx_info->entry_ctrls.guest_ia32e = 1;
		    }
		} else {
		    if (hw_efer->lme) {
			PrintDebug("Enabling long mode\n");
			
			hw_efer->lma = 1;
			vmx_info->entry_ctrls.guest_ia32e = 1;
		    }
 		}
		
		//            PrintDebug("Activating Shadow Page tables\n");
		
		if (core->shdw_pg_mode == SHADOW_PAGING) {
		    if (v3_activate_shadow_pt(core) == -1) {
			PrintError("Failed to activate shadow page tables\n");
			return -1;
		    }
		}
		
	    } else {

		if (core->shdw_pg_mode == SHADOW_PAGING) {
		    if (v3_activate_passthrough_pt(core) == -1) {
			PrintError("Failed to activate passthrough page tables\n");
			return -1;
		    }
		} else {
		    // This is hideous... Let's hope that the 1to1 page table has not been nuked...
		    core->ctrl_regs.cr3 = VMXASSIST_1to1_PT;
		}
	    }
	}
    }

    return 0;
}

static v3_reg_t * 
get_reg_ptr(struct v3_core_info     * core, 
	    struct vmx_exit_cr_qual * cr_qual) 
{
    v3_reg_t * reg = NULL;

    switch (cr_qual->gpr) {
	case 0:
	    reg = &(core->vm_regs.rax);
	    break;
	case 1:
	    reg = &(core->vm_regs.rcx);
	    break;
	case 2:
	    reg = &(core->vm_regs.rdx);
	    break;
	case 3:
	    reg = &(core->vm_regs.rbx);
	    break;
	case 4:
	    reg = &(core->vm_regs.rsp);
	    break;
	case 5:
	    reg = &(core->vm_regs.rbp);
	    break;
	case 6:
	    reg = &(core->vm_regs.rsi);
	    break;
	case 7:
	    reg = &(core->vm_regs.rdi);
	    break;
	case 8:
	    reg = &(core->vm_regs.r8);
	    break;
	case 9:
	    reg = &(core->vm_regs.r9);
	    break;
	case 10:
	    reg = &(core->vm_regs.r10);
	    break;
	case 11:
	    reg = &(core->vm_regs.r11);
	    break;
	case 12:
	    reg = &(core->vm_regs.r11);
	    break;
	case 13:
	    reg = &(core->vm_regs.r13);
	    break;
	case 14:
	    reg = &(core->vm_regs.r14);
	    break;
	case 15:
	    reg = &(core->vm_regs.r15);
	    break;
    }

    return reg;
}


